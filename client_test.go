// Copyright 2024 Matt Schultz <schultz@sent.com>. All rights reserved.
// Use of this source code is governed by an ISC license that can be found in the LICENSE file.

package rcon_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/schultz-is/rcon-go"
)

func TestClient(t *testing.T) {
	t.Run(
		"successful auth",
		func(t *testing.T) {
			testClientWithHandler(
				t,

				// Client
				func(conn net.Conn, errCh chan error) {
					c := rcon.NewClient(conn, rcon.ClientConfig{})

					if err := c.Authorize(context.Background(), "password goes here"); err != nil {
						errCh <- fmt.Errorf("Failed to authorize: %s", err)
						return
					}
				},

				// Server
				func(conn net.Conn, errCh chan error) {
					var req rcon.Packet
					if _, err := req.ReadFrom(conn); err != nil {
						errCh <- fmt.Errorf("Failed to read auth request packet from client: %s", err)
						return
					}

					resp := rcon.Packet{
						ID:   0,
						Type: rcon.PacketTypeAuthResponse,
					}
					if _, err := resp.WriteTo(conn); err != nil {
						errCh <- fmt.Errorf("Failed to send auth response packet to client: %s", err)
						return
					}
				},
			)
		},
	)

	t.Run(
		"successful exec command",
		func(t *testing.T) {
			wantResp := rcon.Packet{
				ID:   321,
				Type: rcon.PacketTypeResponseValue,
				Body: []byte("nothing to see here..."),
			}

			testClientWithHandler(
				t,

				// Client
				func(conn net.Conn, errCh chan error) {
					c := rcon.NewClient(conn, rcon.ClientConfig{})

					resp, err := c.ExecCommand(context.Background(), []byte("info"))
					if err != nil {
						errCh <- fmt.Errorf("Client exec command failed: %s", err)
						return
					}
					if !bytes.Equal(resp, wantResp.Body) {
						errCh <- fmt.Errorf("Exec command response mismatch, got: %0x, want: %0x", resp, wantResp.Body)
						return
					}
				},

				// Server
				func(conn net.Conn, errCh chan error) {
					var req rcon.Packet
					if _, err := req.ReadFrom(conn); err != nil {
						errCh <- fmt.Errorf("Failed to read exec command request packet from client: %s", err)
						return
					}
					if _, err := wantResp.WriteTo(conn); err != nil {
						errCh <- fmt.Errorf("Failed to send exec command response packet to client: %s", err)
						return
					}
				},
			)
		},
	)

	t.Run(
		"unauthed exec command",
		func(t *testing.T) {
			testClientWithHandler(
				t,

				// Client
				func(conn net.Conn, errCh chan error) {
					c := rcon.NewClient(conn, rcon.ClientConfig{})
					if _, err := c.ExecCommand(context.Background(), []byte("info")); err == nil {
						errCh <- fmt.Errorf("Unauthed exec command unexpectedly succeeded")
						return
					}
				},

				// Server
				func(conn net.Conn, errCh chan error) {
					var req rcon.Packet
					if _, err := req.ReadFrom(conn); err != nil {
						errCh <- fmt.Errorf("Failed to read exec command request packet from client: %s", err)
						return
					}
					resp := rcon.Packet{
						ID:   -1,
						Type: rcon.PacketTypeAuthResponse,
					}
					if _, err := resp.WriteTo(conn); err != nil {
						errCh <- fmt.Errorf("Failed to send auth response packet to client: %s", err)
						return
					}
				},
			)
		},
	)

	t.Run(
		"write to a closed conn",
		func(t *testing.T) {
			testClientWithHandler(
				t,

				// Client
				func(conn net.Conn, errCh chan error) {
					c := rcon.NewClient(conn, rcon.ClientConfig{})
					if err := c.Close(); err != nil {
						errCh <- fmt.Errorf("Problem closing client: %s", err)
						return
					}
					if _, err := c.ExecCommand(context.Background(), []byte("info")); err == nil {
						errCh <- fmt.Errorf("Write to a closed connection unexpectedly succeeded")
						return
					}
				},

				// Server
				func(conn net.Conn, errCh chan error) {
					var req rcon.Packet
					_, _ = req.ReadFrom(conn)
				},
			)
		},
	)

	t.Run(
		"read from a closed conn",
		func(t *testing.T) {
			testClientWithHandler(
				t,

				// Client
				func(conn net.Conn, errCh chan error) {
					c := rcon.NewClient(conn, rcon.ClientConfig{})
					if _, err := c.ExecCommand(context.Background(), []byte("info")); err == nil {
						errCh <- fmt.Errorf("Read from a closed connection unexpectedly succeeded")
						return
					}
				},

				// Server
				func(conn net.Conn, errCh chan error) {
					var req rcon.Packet
					if _, err := req.ReadFrom(conn); err != nil {
						errCh <- fmt.Errorf("Failed to read exec command request packet from client: %s", err)
						return
					}

					if err := conn.Close(); err != nil {
						errCh <- fmt.Errorf("Problem closing server: %s", err)
						return
					}

					resp := rcon.Packet{}
					if _, err := resp.WriteTo(conn); err == nil {
						errCh <- fmt.Errorf("Write to a closed connection unexpectedly succeeded")
						return
					}
				},
			)
		},
	)

	t.Run(
		"request timeout",
		func(t *testing.T) {
			testClientWithHandler(
				t,

				// Client
				func(conn net.Conn, errCh chan error) {
					c := rcon.NewClient(
						conn,
						rcon.ClientConfig{Timeout: 1 * time.Nanosecond},
					)

					if _, err := c.ExecCommand(context.Background(), []byte("info")); err == nil {
						errCh <- errors.New("Exec command did not time out as expected")
					}
				},

				// Server
				func(conn net.Conn, errCh chan error) {
					// NOOP in order to force a timeout.
				},
			)
		},
	)

	t.Run(
		"negative starting seq set to 0",
		func(t *testing.T) {
			testClientWithHandler(
				t,

				// Client
				func(conn net.Conn, errCh chan error) {
					c := rcon.NewClient(
						conn,
						rcon.ClientConfig{StartingSeq: math.MinInt32},
					)

					if _, err := c.ExecCommand(context.Background(), []byte("info")); err != nil {
						errCh <- fmt.Errorf("Failed exec command: %s", err)
						return
					}
				},

				// Server
				func(conn net.Conn, errCh chan error) {
					var req rcon.Packet
					if _, err := req.ReadFrom(conn); err != nil {
						errCh <- fmt.Errorf("Failed to read exec command request packet from client: %s", err)
						return
					}
					if req.ID != 0 {
						errCh <- fmt.Errorf("Expected request packet to have ID of 0, got: %d", req.ID)
						return
					}

					resp := rcon.Packet{}
					if _, err := resp.WriteTo(conn); err != nil {
						errCh <- fmt.Errorf("Failed to write exec command response packet to client: %s", err)
						return
					}
				},
			)
		},
	)

	t.Run(
		"math.MaxInt32 starting seq wraps to 0",
		func(t *testing.T) {
			testClientWithHandler(
				t,

				// Client
				func(conn net.Conn, errCh chan error) {
					c := rcon.NewClient(
						conn,
						rcon.ClientConfig{StartingSeq: math.MaxInt32},
					)

					if _, err := c.ExecCommand(context.Background(), []byte("info")); err != nil {
						errCh <- fmt.Errorf("Failed exec command: %s", err)
						return
					}

					if _, err := c.ExecCommand(context.Background(), []byte("info")); err != nil {
						errCh <- fmt.Errorf("Failed exec command: %s", err)
						return
					}
				},

				// Server
				func(conn net.Conn, errCh chan error) {
					var req rcon.Packet
					if _, err := req.ReadFrom(conn); err != nil {
						errCh <- fmt.Errorf("Failed to read exec command request packet from client: %s", err)
						return
					}
					if req.ID != math.MaxInt32 {
						errCh <- fmt.Errorf("Expected request packet to have ID of math.MaxInt32, got: %d", req.ID)
						return
					}

					resp := rcon.Packet{}
					if _, err := resp.WriteTo(conn); err != nil {
						errCh <- fmt.Errorf("Failed to write exec command response packet to client: %s", err)
						return
					}

					if _, err := req.ReadFrom(conn); err != nil {
						errCh <- fmt.Errorf("Failed to read exec command request packet from client: %s", err)
						return
					}
					if req.ID != 0 {
						errCh <- fmt.Errorf("Expected request packet to have ID of 0, got: %d", req.ID)
						return
					}

					if _, err := resp.WriteTo(conn); err != nil {
						errCh <- fmt.Errorf("Failed to write exec command response packet to client: %s", err)
						return
					}
				},
			)
		},
	)

	t.Run(
		"outbound auth packets are sanitized",
		func(t *testing.T) {
			password := "password"
			testClientWithHandler(
				t,

				// Client
				func(conn net.Conn, errCh chan error) {
					c := rcon.NewClient(
						conn,
						rcon.ClientConfig{
							Logger: slog.New(&testLogger{t, password}),
						},
					)

					err := c.Authorize(context.Background(), password)
					if err != nil {
						errCh <- fmt.Errorf("Failed to authorize: %s", err)
						return
					}
				},

				// Server
				func(conn net.Conn, errCh chan error) {
					var req rcon.Packet
					_, err := req.ReadFrom(conn)
					if err != nil {
						errCh <- fmt.Errorf("Failed to read auth request packet from client: %s", err)
						return
					}

					resp := rcon.Packet{
						ID:   0,
						Type: rcon.PacketTypeAuthResponse,
					}
					_, err = resp.WriteTo(conn)
					if err != nil {
						errCh <- fmt.Errorf("Failed to write auth response packet to client: %s", err)
						return
					}
				},
			)
		},
	)
}

// testLogger is the simplest implementation of a slog.Logger necessary to ensure outbound
// authorization packets are scrubbed of sensitive information.
type testLogger struct {
	t        *testing.T
	password string
}

func (l *testLogger) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (l *testLogger) WithAttrs(_ []slog.Attr) slog.Handler         { return l }
func (l *testLogger) WithGroup(_ string) slog.Handler              { return l }
func (l *testLogger) Handle(_ context.Context, r slog.Record) error {
	if strings.Contains(r.Message, hex.EncodeToString([]byte(l.password))) {
		l.t.Fatal("Outbound authorization packet was not scrubbed from logs")
	}
	return nil
}

type testHandler func(conn net.Conn, errCh chan error)

func testClientWithHandler(t *testing.T, clientHandler, serverHandler testHandler) {
	cc, sc := net.Pipe()
	defer cc.Close()
	defer sc.Close()

	doneN := 0
	doneCh := make(chan struct{})
	errCh := make(chan error)
	timer := time.NewTimer(1 * time.Second)

	go func() {
		defer func() { doneCh <- struct{}{} }()
		clientHandler(cc, errCh)
	}()
	go func() {
		defer func() { doneCh <- struct{}{} }()
		serverHandler(sc, errCh)
	}()

	for {
		select {
		case <-doneCh:
			doneN += 1
			if doneN >= 2 {
				return
			}

		case err := <-errCh:
			t.Fatal(err.Error())
			return

		case <-timer.C:
			t.Fatal("Test timeout reached")
			return
		}
	}
}
