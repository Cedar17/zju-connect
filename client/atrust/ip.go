package atrust

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/mythologyli/zju-connect/log"
)

func (c *Client) getIP() error {
	ctx := c.lifecycleCtx
	if ctx == nil {
		ctx = context.Background()
	}
	return c.getIPContext(ctx)
}

func (c *Client) getIPContext(parent context.Context) error {
	if parent == nil {
		parent = context.Background()
	}
	addr := c.BestNodes[c.MajorNodeGroup]
	if addr == "" {
		for _, node := range c.BestNodes {
			addr = node
			break
		}
	}
	if addr == "" {
		return fmt.Errorf("no reachable node for ip request")
	}

	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	conn, err := c.underlayDialer.DialTLSContext(ctx, "tcp", addr, tunnelTLSConfig())
	if err != nil {
		return contextError(ctx, err)
	}
	stopClose := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stopClose()
	defer func(conn *tls.Conn) {
		_ = conn.Close()
	}(conn)
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return err
		}
	}

	msg := []byte{0x05, 0x01, 0xd0, 0x53, 0x00, 0x00, 0x53}
	msg = append(msg, []byte(fmt.Sprintf(`{"sid":"%s"}`, c.SID))...)
	if _, err := conn.Write(msg); err != nil {
		return contextError(ctx, err)
	}

	msg = []byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := conn.Write(msg); err != nil {
		return contextError(ctx, err)
	}

	for {
		header := make([]byte, 2)
		_, err = io.ReadFull(conn, header)
		if err != nil {
			return contextError(ctx, err)
		}
		if header[0] == 0x53 && header[1] == 0x00 {
			lengthBytes := make([]byte, 2)
			_, err = io.ReadFull(conn, lengthBytes)
			if err != nil {
				return contextError(ctx, err)
			}
			length := binary.BigEndian.Uint16(lengthBytes)
			data := make([]byte, length)
			_, err = io.ReadFull(conn, data)
			if err != nil {
				return contextError(ctx, err)
			}

			if !strings.Contains(string(data), "OK") {
				return fmt.Errorf("failed to connect to the server: %s", string(data))
			}
		} else if header[0] == 0x05 && header[1] == 0x00 {
			data := make([]byte, 6)
			_, err = io.ReadFull(conn, data)
			if err != nil {
				return contextError(ctx, err)
			}
			if data[0] != 0x00 || data[1] != 0x01 {
				return fmt.Errorf("unexpected response: %x", data)
			}

			ip := net.IPv4(data[2], data[3], data[4], data[5])
			c.setIP(ip)
			log.Printf("Received IP: %s", ip.String())
			return nil
		}
	}
}

func contextError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return err
}
