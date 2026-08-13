package atrust

import (
	"errors"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/mythologyli/zju-connect/log"
)

// ErrL3TunnelRecovering reports that a packet could not be accepted while the
// tunnel reconnects. Callers should keep the surrounding VPN session alive and
// retry through their normal transport semantics.
var ErrL3TunnelRecovering = errors.New("l3 tunnel is recovering")

var (
	errL3TunnelAuthentication = errors.New("l3 tunnel authentication failed")
	errL3TunnelConfiguration  = errors.New("l3 tunnel configuration unavailable")
)

// L3TunnelState is the recoverable lifecycle exposed by an L3Conn.
type L3TunnelState string

const (
	L3TunnelStateActive     L3TunnelState = "active"
	L3TunnelStateRecovering L3TunnelState = "recovering"
	L3TunnelStateFailed     L3TunnelState = "failed"
)

// L3TunnelFailure is a safe, stable category for a permanent L3 failure.
type L3TunnelFailure string

const (
	L3TunnelFailureAuthentication L3TunnelFailure = "authentication"
	L3TunnelFailureConfiguration  L3TunnelFailure = "configuration"
)

// L3TunnelEvent contains no endpoint, credential, or raw transport error.
type L3TunnelEvent struct {
	State   L3TunnelState
	Failure L3TunnelFailure
}

type l3TunnelRecovery struct {
	wake chan struct{}
}

func (t *L3Tunnel) startRecovery(nodeGroupID string, reportImmediately bool) {
	if t.client == nil || t.connect == nil {
		return
	}
	select {
	case <-t.closeCh:
		return
	default:
	}

	t.connsMu.Lock()
	if t.conns[nodeGroupID] != nil || t.failedGroups[nodeGroupID] != nil {
		t.connsMu.Unlock()
		return
	}
	if recovery := t.recoveries[nodeGroupID]; recovery != nil {
		t.connsMu.Unlock()
		if reportImmediately {
			t.markGroupRecovering(nodeGroupID)
		}
		t.nudgeRecovery(recovery)
		return
	}
	if t.recoveries == nil {
		t.recoveries = make(map[string]*l3TunnelRecovery)
	}
	recovery := &l3TunnelRecovery{wake: make(chan struct{}, 1)}
	t.recoveries[nodeGroupID] = recovery
	t.connsMu.Unlock()

	if reportImmediately {
		t.markGroupRecovering(nodeGroupID)
	}
	go t.runRecovery(nodeGroupID, recovery)
}

func (t *L3Tunnel) nudgeRecovery(recovery *l3TunnelRecovery) {
	if recovery == nil {
		return
	}
	select {
	case recovery.wake <- struct{}{}:
	default:
	}
}

func (t *L3Tunnel) runRecovery(nodeGroupID string, recovery *l3TunnelRecovery) {
	failures := 0
	var lastAttempt time.Time
	for {
		if failures > 0 && !t.waitForRecoveryAttempt(recovery, failures, lastAttempt) {
			return
		}
		lastAttempt = time.Now()
		conn, err := t.connectConn(nodeGroupID)
		if err == nil {
			t.finishRecovery(nodeGroupID, recovery, conn)
			return
		}
		if failure, permanent := permanentL3Failure(err); permanent {
			t.finishRecoveryFailure(nodeGroupID, recovery, err, failure)
			return
		}
		failures++
		t.markGroupRecovering(nodeGroupID)
		log.DebugPrintf("l3-tunnel recovery attempt %d failed for group %s: %v", failures, nodeGroupID, err)
	}
}

func (t *L3Tunnel) waitForRecoveryAttempt(recovery *l3TunnelRecovery, failures int, lastAttempt time.Time) bool {
	delay := t.recoveryBackoff(failures)
	deadline := time.Now().Add(delay)
	timer := time.NewTimer(delay)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			return true
		case <-recovery.wake:
			minimum := t.reconnectDemand
			if minimum <= 0 {
				minimum = defaultReconnectDemandInterval
			}
			demandDeadline := lastAttempt.Add(minimum)
			if !demandDeadline.Before(deadline) {
				continue
			}
			deadline = demandDeadline
			remaining := time.Until(deadline)
			if remaining < 0 {
				remaining = 0
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(remaining)
		case <-t.closeCh:
			return false
		}
	}
}

func (t *L3Tunnel) recoveryBackoff(failures int) time.Duration {
	backoff := t.reconnectBackoff
	if len(backoff) == 0 {
		backoff = defaultReconnectBackoff
	}
	index := failures - 1
	if index < 0 {
		index = 0
	}
	if index >= len(backoff) {
		index = len(backoff) - 1
	}
	return backoff[index]
}

func (t *L3Tunnel) finishRecovery(nodeGroupID string, recovery *l3TunnelRecovery, conn *l3TunnelConn) {
	t.connsMu.Lock()
	if t.recoveries[nodeGroupID] != recovery {
		t.connsMu.Unlock()
		_ = conn.Close()
		return
	}
	delete(t.recoveries, nodeGroupID)
	delete(t.failedGroups, nodeGroupID)
	select {
	case <-t.closeCh:
		t.connsMu.Unlock()
		_ = conn.Close()
		return
	default:
		t.conns[nodeGroupID] = conn
	}
	t.connsMu.Unlock()

	go t.forwardFromConn(nodeGroupID, conn)
	t.markGroupActive(nodeGroupID)
}

func (t *L3Tunnel) finishRecoveryFailure(nodeGroupID string, recovery *l3TunnelRecovery, err error, failure L3TunnelFailure) {
	t.connsMu.Lock()
	if t.recoveries[nodeGroupID] != recovery {
		t.connsMu.Unlock()
		return
	}
	delete(t.recoveries, nodeGroupID)
	if t.failedGroups == nil {
		t.failedGroups = make(map[string]error)
	}
	t.failedGroups[nodeGroupID] = err
	t.connsMu.Unlock()
	t.markGroupFailed(nodeGroupID, failure)
}

func permanentL3Failure(err error) (L3TunnelFailure, bool) {
	switch {
	case errors.Is(err, errL3TunnelAuthentication):
		return L3TunnelFailureAuthentication, true
	case errors.Is(err, errL3TunnelConfiguration):
		return L3TunnelFailureConfiguration, true
	default:
		return "", false
	}
}

func (t *L3Tunnel) markGroupRecovering(nodeGroupID string) {
	t.eventsMu.Lock()
	if t.recoveringGroups == nil {
		t.recoveringGroups = make(map[string]struct{})
	}
	_, alreadyRecovering := t.recoveringGroups[nodeGroupID]
	t.recoveringGroups[nodeGroupID] = struct{}{}
	if !alreadyRecovering && len(t.recoveringGroups) == 1 && t.terminalFailure == "" {
		t.publishEventLocked(L3TunnelEvent{State: L3TunnelStateRecovering})
	}
	t.eventsMu.Unlock()
}

func (t *L3Tunnel) markGroupActive(nodeGroupID string) {
	t.eventsMu.Lock()
	_, wasRecovering := t.recoveringGroups[nodeGroupID]
	delete(t.recoveringGroups, nodeGroupID)
	if wasRecovering && len(t.recoveringGroups) == 0 && t.terminalFailure == "" {
		t.publishEventLocked(L3TunnelEvent{State: L3TunnelStateActive})
	}
	t.eventsMu.Unlock()
}

func (t *L3Tunnel) markGroupFailed(nodeGroupID string, failure L3TunnelFailure) {
	t.eventsMu.Lock()
	delete(t.recoveringGroups, nodeGroupID)
	t.terminalFailure = failure
	t.publishEventLocked(L3TunnelEvent{State: L3TunnelStateFailed, Failure: failure})
	t.eventsMu.Unlock()
}

func (t *L3Tunnel) subscribeEvents(conn *L3Conn) chan L3TunnelEvent {
	events := make(chan L3TunnelEvent, 8)
	t.eventsMu.Lock()
	if t.eventSubscribers == nil {
		t.eventSubscribers = make(map[*L3Conn]chan L3TunnelEvent)
	}
	t.eventSubscribers[conn] = events
	if t.terminalFailure != "" {
		events <- L3TunnelEvent{State: L3TunnelStateFailed, Failure: t.terminalFailure}
	} else if len(t.recoveringGroups) > 0 {
		events <- L3TunnelEvent{State: L3TunnelStateRecovering}
	}
	t.eventsMu.Unlock()
	return events
}

func (t *L3Tunnel) unsubscribeEvents(conn *L3Conn) {
	t.eventsMu.Lock()
	if events := t.eventSubscribers[conn]; events != nil {
		delete(t.eventSubscribers, conn)
		close(events)
	}
	t.eventsMu.Unlock()
}

func (t *L3Tunnel) closeEventSubscribers() {
	t.eventsMu.Lock()
	for conn, events := range t.eventSubscribers {
		delete(t.eventSubscribers, conn)
		close(events)
	}
	t.eventsMu.Unlock()
}

func (t *L3Tunnel) publishEventLocked(event L3TunnelEvent) {
	for _, events := range t.eventSubscribers {
		select {
		case events <- event:
		default:
			select {
			case <-events:
			default:
			}
			events <- event
		}
	}
}

func isRecoverableL3TransportError(err error) bool {
	if err == nil {
		return false
	}
	if isClosedConnErr(err) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, io.ErrShortWrite) || errors.Is(err, net.ErrWriteToConnected) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.EPIPE, syscall.ECONNABORTED, syscall.ECONNRESET, syscall.ETIMEDOUT,
			syscall.ENETDOWN, syscall.ENETUNREACH, syscall.EHOSTUNREACH:
			return true
		}
	}
	var netErr net.Error
	return errors.As(err, &netErr)
}
