package atrust

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"testing"
	"time"
)

func startSetupNodeServer(t *testing.T) string {
	t.Helper()
	listener := newTestTLSListener(t)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				first := make([]byte, 1)
				if _, err := io.ReadFull(conn, first); err != nil {
					return
				}
				if first[0] != 0x05 {
					return
				}
				// getIP accepts this SOCKS-style virtual-IP response. Probe
				// connections never write an application payload and close above.
				_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 10, 0, 0, 2})
			}(conn)
		}
	}()
	return listener.Addr().String()
}

func resourceForTestNode(address string) []byte {
	return []byte(fmt.Sprintf(`{
		"data": {
			"appList": {
				"data": {
					"config": {
						"nodeGroupConf": {
							"majorNodeGroup": {"id": "group"},
							"nodeGroupList": [{
								"id": "group",
								"addressInfo": [{"address": %q, "type": "wan"}]
							}]
						}
					}
				}
			}
		}
	}`, address))
}

func TestSetupContextReportsFixedStageOrderAndSetupRemainsCompatible(t *testing.T) {
	address := startSetupNodeServer(t)
	wantStages := []string{
		"prepare.resource",
		"prepare.nodeProbe",
		"prepare.ip",
		"prepare.l3",
		"prepare.complete",
	}
	for _, test := range []struct {
		name  string
		setup func(*Client, []byte) ([]byte, error)
	}{
		{
			name: "context",
			setup: func(client *Client, resource []byte) ([]byte, error) {
				return client.SetupContext(context.Background(), "127.0.0.1", 443, "", "", "", "", "", "", "", "", "", nil, resource, 0, "", false)
			},
		},
		{
			name: "legacy",
			setup: func(client *Client, resource []byte) ([]byte, error) {
				return client.Setup("127.0.0.1", 443, "", "", "", "", "", "", "", "", "", nil, resource, 0, "", false)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := NewClient("user", "sid", "device", "")
			var stages []string
			client.SetSetupStageReporter(func(stage string) {
				stages = append(stages, stage)
			})
			if _, err := test.setup(client, resourceForTestNode(address)); err != nil {
				t.Fatalf("Setup() error = %v", err)
			}
			defer client.Close()
			if !reflect.DeepEqual(stages, wantStages) {
				t.Fatalf("setup stages = %v, want %v", stages, wantStages)
			}
			if got, err := client.IP(); err != nil || !got.Equal(net.IPv4(10, 0, 0, 2)) {
				t.Fatalf("prepared IP = %v, %v; want 10.0.0.2", got, err)
			}
		})
	}
}

func TestSetupContextHonorsCallerDeadlineDuringNodeProbe(t *testing.T) {
	client := NewClient("user", "sid", "device", "")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	startedAt := time.Now()
	_, err := client.SetupContext(ctx, "127.0.0.1", 443, "", "", "", "", "", "", "", "", "", nil, resourceForTestNode("127.0.0.1:1"), 0, "", false)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("SetupContext() error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(startedAt); elapsed > time.Second {
		t.Fatalf("SetupContext() returned after %s, want caller deadline", elapsed)
	}
}
