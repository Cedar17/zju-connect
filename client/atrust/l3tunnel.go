package atrust

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/ipresource"
	"github.com/mythologyli/zju-connect/log"
)

type L3Tunnel struct {
	client *Client

	ip net.IP

	resourceIndex *ipresource.Index

	conns            map[string]*l3TunnelConn
	connsMu          sync.Mutex
	recoveries       map[string]*l3TunnelRecovery
	failedGroups     map[string]error
	connect          func(context.Context, string) (*l3TunnelConn, error)
	reconnectBackoff []time.Duration
	reconnectDemand  time.Duration

	eventsMu         sync.Mutex
	eventSubscribers map[*L3Conn]chan L3TunnelEvent
	recoveringGroups map[string]struct{}
	terminalFailure  L3TunnelFailure

	vipMu   sync.Mutex
	vipList []net.IP

	dataChan  chan []byte
	closeCh   chan struct{}
	closeOnce sync.Once
}

var defaultReconnectBackoff = []time.Duration{
	time.Second,
	2 * time.Second,
	4 * time.Second,
	8 * time.Second,
	16 * time.Second,
	30 * time.Second,
	time.Minute,
	2 * time.Minute,
	5 * time.Minute,
}

const defaultReconnectDemandInterval = 5 * time.Second

func NewL3Tunnel(aTrustClient *Client) (*L3Tunnel, error) {
	t := &L3Tunnel{
		client:           aTrustClient,
		conns:            make(map[string]*l3TunnelConn),
		recoveries:       make(map[string]*l3TunnelRecovery),
		failedGroups:     make(map[string]error),
		reconnectBackoff: append([]time.Duration(nil), defaultReconnectBackoff...),
		reconnectDemand:  defaultReconnectDemandInterval,
		eventSubscribers: make(map[*L3Conn]chan L3TunnelEvent),
		recoveringGroups: make(map[string]struct{}),
		dataChan:         make(chan []byte, 4096),
		closeCh:          make(chan struct{}),
	}
	t.connect = func(ctx context.Context, addr string) (*l3TunnelConn, error) {
		info := clientInfo{
			sid:          aTrustClient.SID,
			deviceID:     aTrustClient.DeviceID,
			connectionID: aTrustClient.ConnectionID,
			username:     aTrustClient.Username,
		}
		dialTLS := func(ctx context.Context, network, address string, _ *tls.Config) (*tls.Conn, error) {
			return aTrustClient.underlayDialer.DialTLSContext(ctx, network, address, aTrustClient.nodeTLSConfigForDial())
		}
		return newL3TunnelConn(ctx, dialTLS, addr, info, aTrustClient.SignKey, t.updateVIP)
	}

	ipResources, err := aTrustClient.IPResources()
	if ipResources == nil {
		ipResources = []client.IPResource{}
	}
	t.resourceIndex = ipresource.New(ipResources)

	ip, err := aTrustClient.IP()
	if err != nil {
		return nil, fmt.Errorf("failed to get client IP: %v", err)
	}
	t.ip = ip

	return t, nil
}

func (t *L3Tunnel) updateVIP(ips []net.IP) {
	updated := make([]net.IP, 0, len(ips))
	var ipv4 net.IP
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		copyOfIP := append(net.IP(nil), ip...)
		updated = append(updated, copyOfIP)
		if ipv4 == nil && ip.To4() != nil {
			ipv4 = append(net.IP(nil), ip.To4()...)
		}
	}
	t.vipMu.Lock()
	changed := ipv4 != nil && !t.ip.Equal(ipv4)
	t.vipList = updated
	t.vipMu.Unlock()
	if changed && t.client != nil {
		if err := t.client.applyIPUpdate(ipv4); err != nil {
			log.Printf("Failed to apply updated l3-tunnel virtual IP %s: %v", ipv4, err)
			return
		}
		t.vipMu.Lock()
		t.ip = append(net.IP(nil), ipv4...)
		t.vipMu.Unlock()
		t.client.setIP(ipv4)
		t.client.underlayDialer.ExcludeIP(ipv4)
		log.Printf("Updated l3-tunnel virtual IP: %s", ipv4)
	}
}

func (t *L3Tunnel) Close() {
	t.closeOnce.Do(func() {
		if t.closeCh != nil {
			close(t.closeCh)
		}
		t.connsMu.Lock()
		conns := make([]*l3TunnelConn, 0, len(t.conns))
		for _, conn := range t.conns {
			conns = append(conns, conn)
		}
		t.conns = make(map[string]*l3TunnelConn)
		t.connsMu.Unlock()

		for _, conn := range conns {
			_ = conn.Close()
		}
		t.closeEventSubscribers()
	})
}

func (t *L3Tunnel) getConn(nodeGroupID string) (*l3TunnelConn, error) {
	select {
	case <-t.closeCh:
		return nil, net.ErrClosed
	default:
	}

	t.connsMu.Lock()
	conn := t.conns[nodeGroupID]
	failure := t.failedGroups[nodeGroupID]
	recovery := t.recoveries[nodeGroupID]
	t.connsMu.Unlock()
	if conn != nil {
		return conn, nil
	}
	if failure != nil {
		return nil, failure
	}
	if recovery == nil {
		t.startRecovery(nodeGroupID, false)
	} else {
		t.nudgeRecovery(recovery)
	}
	return nil, ErrL3TunnelRecovering
}

func (t *L3Tunnel) connectConn(nodeGroupID string) (*l3TunnelConn, error) {
	t.client.BestNodesRWMutex.RLock()
	addr := t.client.BestNodes[nodeGroupID]
	if addr == "" {
		addr = t.client.BestNodes[t.client.MajorNodeGroup]
	}
	t.client.BestNodesRWMutex.RUnlock()
	if addr == "" {
		return nil, fmt.Errorf("%w: no available node for group %s", errL3TunnelConfiguration, nodeGroupID)
	}

	ctx, cancel := context.WithTimeout(t.client.lifecycleCtx, 10*time.Second)
	defer cancel()
	return t.connect(ctx, addr)
}

func (t *L3Tunnel) evictConn(nodeGroupID string, conn *l3TunnelConn) {
	t.connsMu.Lock()
	removed := false
	if existing := t.conns[nodeGroupID]; existing == conn {
		delete(t.conns, nodeGroupID)
		removed = true
	}
	t.connsMu.Unlock()
	if removed {
		_ = conn.Close()
	}
}

func (t *L3Tunnel) evictStaleConns(bestNodes map[string]string, majorNodeGroup string) {
	t.connsMu.Lock()
	stale := make([]*l3TunnelConn, 0)
	for group, conn := range t.conns {
		addr := bestNodes[group]
		if addr == "" {
			addr = bestNodes[majorNodeGroup]
		}
		if addr != "" && conn.addr != addr {
			delete(t.conns, group)
			stale = append(stale, conn)
		}
	}
	t.connsMu.Unlock()

	for _, conn := range stale {
		log.DebugPrintf("l3-tunnel best node changed, closing stale connection to %s", conn.addr)
		_ = conn.Close()
	}
}

func (t *L3Tunnel) forwardFromConn(nodeGroupID string, conn *l3TunnelConn) {
	for {
		pkt, err := conn.ReadPacket()
		if err != nil {
			t.evictConn(nodeGroupID, conn)
			t.startReconnect(nodeGroupID)
			return
		}
		logPacket("recv", pkt)
		select {
		case t.dataChan <- pkt:
		case <-t.closeCh:
			return
		case <-conn.closeCh:
			return
		}
	}
}

func (t *L3Tunnel) startReconnect(nodeGroupID string) {
	t.startRecovery(nodeGroupID, true)
}
