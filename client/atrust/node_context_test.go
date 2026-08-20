package atrust

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestGetBestReachableNodesContextCancelsActiveProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, err := getBestReachableNodesContext(ctx, map[string][]string{
			"group": {"node.example.test:443"},
		}, func(ctx context.Context, _, _ string) (net.Conn, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		})
		result <- err
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("node probe never entered its dial")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("getBestReachableNodesContext() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("node probe did not return after cancellation")
	}
}
