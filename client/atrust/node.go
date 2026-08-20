package atrust

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mythologyli/zju-connect/internal/ping"
	"github.com/mythologyli/zju-connect/log"
)

const pingNum = 3

type NodeGroup struct {
	WAN []string
	LAN []string
}

type nodeGroupsProbeFunc func(map[string][]string) map[string]string

func getBestNodes(nodeGroups map[string]NodeGroup, dialContext func(context.Context, string, string) (net.Conn, error)) map[string]string {
	return selectBestNodes(nodeGroups, func(nodeGroups map[string][]string) map[string]string {
		return getBestReachableNodes(nodeGroups, dialContext)
	})
}

func getBestNodesContext(ctx context.Context, nodeGroups map[string]NodeGroup, dialContext func(context.Context, string, string) (net.Conn, error)) (map[string]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	wanNodeGroups := make(map[string][]string, len(nodeGroups))
	for group, nodes := range nodeGroups {
		wanNodeGroups[group] = nodes.WAN
	}
	bestNodes, err := getBestReachableNodesContext(ctx, wanNodeGroups, dialContext)
	if err != nil {
		return nil, err
	}

	fallbackNodeGroups := make(map[string][]string)
	for group, nodes := range nodeGroups {
		if bestNodes[group] == "" && len(nodes.LAN) > 0 {
			fallbackNodeGroups[group] = nodes.LAN
		}
	}
	if len(fallbackNodeGroups) == 0 {
		return bestNodes, nil
	}
	fallbackNodes, err := getBestReachableNodesContext(ctx, fallbackNodeGroups, dialContext)
	if err != nil {
		return nil, err
	}
	for group, node := range fallbackNodes {
		bestNodes[group] = node
	}
	return bestNodes, nil
}

func selectBestNodes(nodeGroups map[string]NodeGroup, probe nodeGroupsProbeFunc) map[string]string {
	wanNodeGroups := make(map[string][]string, len(nodeGroups))
	for group, nodes := range nodeGroups {
		wanNodeGroups[group] = nodes.WAN
	}
	bestNodes := probe(wanNodeGroups)

	fallbackNodeGroups := make(map[string][]string)
	for group, nodes := range nodeGroups {
		if bestNodes[group] == "" && len(nodes.LAN) > 0 {
			fallbackNodeGroups[group] = nodes.LAN
		}
	}

	if len(fallbackNodeGroups) == 0 {
		return bestNodes
	}
	for group, node := range probe(fallbackNodeGroups) {
		bestNodes[group] = node
	}
	return bestNodes
}

func getBestReachableNodes(nodeGroups map[string][]string, dialContext func(context.Context, string, string) (net.Conn, error)) map[string]string {
	bestNodes, _ := getBestReachableNodesContext(context.Background(), nodeGroups, dialContext)
	return bestNodes
}

func getBestReachableNodesContext(ctx context.Context, nodeGroups map[string][]string, dialContext func(context.Context, string, string) (net.Conn, error)) (map[string]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	bestNodes := make(map[string]string)
	for group, nodes := range nodeGroups {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(nodes) > 0 {
			type nodeProbe struct {
				node   string
				tcping *ping.TCPing
				done   <-chan struct{}
			}
			var probes []nodeProbe

			for _, node := range nodes {
				parts := strings.Split(node, ":")
				host := parts[0]
				port, err := strconv.Atoi(parts[1])
				if err != nil {
					continue
				}

				tcping := ping.NewTCPing()
				tcping.SetDialContext(dialContext)
				target := ping.Target{
					Protocol: ping.TCP,
					Host:     host,
					Port:     port,
					Counter:  pingNum,
					Interval: time.Duration(0.5 * float64(time.Second)),
					Timeout:  time.Duration(1 * float64(time.Second)),
				}
				tcping.SetTarget(&target)

				probes = append(probes, nodeProbe{
					node:   node,
					tcping: tcping,
					done:   tcping.StartContext(ctx),
				})
			}

			for _, probe := range probes {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-probe.done:
				}
			}

			bestScore := time.Duration(0)
			bestNode := ""
			for _, probe := range probes {
				result := probe.tcping.Result()
				score, reachable := nodeProbeScore(result)
				if reachable && (bestScore == 0 || score < bestScore) {
					bestNode = probe.node
					bestScore = score
				}
			}

			if bestNode != "" {
				bestNodes[group] = bestNode
				log.Printf("Best node in group %s: %s with quality score %d ms", group, bestNode, bestScore.Milliseconds())
			}
		}
	}

	return bestNodes, nil
}

func nodeProbeScore(result *ping.Result) (time.Duration, bool) {
	if result == nil || result.SuccessCounter == 0 {
		return 0, false
	}
	penalty := time.Second
	if result.Target != nil && result.Target.Timeout > 0 {
		penalty = result.Target.Timeout
	}
	return result.Avg() + time.Duration(result.Failed())*penalty, true
}

func (c *Client) updateBestNodes(ctx context.Context, updateBestNodesInterval int) {
	ticker := time.NewTicker(time.Duration(updateBestNodesInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		bestNodes, err := getBestNodesContext(ctx, c.NodeGroups, c.underlayDialer.DialContext)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("Failed to update best nodes: %v", err)
			continue
		}
		c.BestNodesRWMutex.Lock()
		c.BestNodes = bestNodes
		c.BestNodesRWMutex.Unlock()

		c.l3TunnelMu.Lock()
		tunnel := c.l3Tunnel
		c.l3TunnelMu.Unlock()
		if tunnel != nil {
			tunnel.evictStaleConns(bestNodes, c.MajorNodeGroup)
		}
	}
}
