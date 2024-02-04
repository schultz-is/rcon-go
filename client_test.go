package rcon_test

import (
	"bytes"
	"context"
	"encoding/hex"
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
			cc, sc := net.Pipe()
			defer func() {
				_ = cc.Close()
				_ = sc.Close()
			}()

			c := rcon.NewClient(cc, rcon.ClientConfig{})

			go func() {
				var req rcon.Packet
				_, err := req.ReadFrom(sc)
				if err != nil {
					t.Fatalf("Failed to read auth request packet from client: %s", err)
				}
				resp := rcon.Packet{
					ID:   0,
					Type: rcon.PacketTypeAuthResponse,
				}
				_, err = resp.WriteTo(sc)
				if err != nil {
					t.Fatalf("Failed to send auth response packet to client: %s", err)
				}
			}()

			err := c.Authorize(context.Background(), "password goes here")
			if err != nil {
				t.Fatalf("Client authorize failed: %s", err)
			}
		},
	)

	t.Run(
		"successful exec command",
		func(t *testing.T) {
			cc, sc := net.Pipe()
			defer func() {
				_ = cc.Close()
				_ = sc.Close()
			}()

			wantResp := rcon.Packet{
				ID:   321,
				Type: rcon.PacketTypeResponseValue,
				Body: []byte("nothing to see here"),
			}

			c := rcon.NewClient(cc, rcon.ClientConfig{})

			go func() {
				var req rcon.Packet
				_, err := req.ReadFrom(sc)
				if err != nil {
					t.Fatalf("Failed to read exec command request packet from client: %s", err)
				}
				wantResp.WriteTo(sc)
				if err != nil {
					t.Fatalf("Failed to send exec command response packet to client: %s", err)
				}
			}()

			resp, err := c.ExecCommand(context.Background(), []byte("info"))
			if err != nil {
				t.Fatalf("Client exec command failed: %s", err)
			}
			if !bytes.Equal(resp, wantResp.Body) {
				t.Fatalf("Exec command response mismatch, got: %0x, want: %0x", resp, wantResp.Body)
			}
		},
	)

	t.Run(
		"unauthed exec command",
		func(t *testing.T) {
			cc, sc := net.Pipe()
			defer func() {
				_ = cc.Close()
				_ = sc.Close()
			}()

			c := rcon.NewClient(cc, rcon.ClientConfig{})

			go func() {
				var req rcon.Packet
				_, err := req.ReadFrom(sc)
				if err != nil {
					t.Fatalf("Failed to read exec command request packet from client: %s", err)
				}
				resp := rcon.Packet{
					ID:   -1,
					Type: rcon.PacketTypeAuthResponse,
				}
				_, err = resp.WriteTo(sc)
				if err != nil {
					t.Fatalf("Failed to send auth response packet to client: %s", err)
				}
			}()

			_, err := c.ExecCommand(context.Background(), []byte("info"))
			if err == nil {
				t.Fatal("Unauthed exec command unexpectedly succeeded")
			}
		},
	)

	t.Run(
		"write to a closed conn",
		func(t *testing.T) {
			cc, sc := net.Pipe()
			defer func() {
				_ = cc.Close()
				_ = sc.Close()
			}()

			c := rcon.NewClient(cc, rcon.ClientConfig{})
			err := c.Close()
			if err != nil {
				t.Fatalf("Problem closing client: %s", err)
			}

			go func() {
				var req rcon.Packet
				_, _ = req.ReadFrom(sc)
			}()

			_, err = c.ExecCommand(context.Background(), []byte("info"))
			if err == nil {
				t.Fatal("Write to a closed connection unexpectedly succeeded")
			}
		},
	)

	t.Run(
		"read from a closed conn",
		func(t *testing.T) {
			cc, sc := net.Pipe()
			defer func() {
				_ = cc.Close()
				_ = sc.Close()
			}()

			c := rcon.NewClient(cc, rcon.ClientConfig{})

			go func() {
				var req rcon.Packet
				_, err := req.ReadFrom(sc)
				if err != nil {
					t.Fatalf("Failed to read exec command request packet from client: %s", err)
				}

				err = sc.Close()
				if err != nil {
					t.Fatalf("Problem closing server: %s", err)
				}

				resp := rcon.Packet{}
				_, err = resp.WriteTo(sc)
				if err == nil {
					t.Fatal("Write to a closed connection unexpectedly succeeded")
				}
			}()

			_, err := c.ExecCommand(context.Background(), []byte("info"))
			if err == nil {
				t.Fatal("Read from a closed connection unexpectedly succeeded")
			}
		},
	)

	t.Run(
		"request timeout",
		func(t *testing.T) {
			cc, sc := net.Pipe()
			defer func() {
				_ = cc.Close()
				_ = sc.Close()
			}()

			c := rcon.NewClient(
				cc,
				rcon.ClientConfig{Timeout: 1 * time.Nanosecond},
			)

			_, err := c.ExecCommand(context.Background(), []byte("info"))
			if err == nil {
				t.Fatal("Exec command did not time out as expected")
			}
		},
	)

	t.Run(
		"negative starting seq set to 0",
		func(t *testing.T) {
			cc, sc := net.Pipe()
			defer func() {
				_ = cc.Close()
				_ = sc.Close()
			}()

			c := rcon.NewClient(
				cc,
				rcon.ClientConfig{StartingSeq: math.MinInt32},
			)

			go func() {
				var req rcon.Packet
				_, err := req.ReadFrom(sc)
				if err != nil {
					t.Fatalf("Failed to read exec command request packet from client: %s", err)
				}

				if req.ID != 0 {
					t.Fatalf("Expected request packet to have ID of 0, got: %d", req.ID)
				}

				resp := rcon.Packet{}
				_, err = resp.WriteTo(sc)
				if err != nil {
					t.Fatalf("Failed to write exec command response packet to client: %s", err)
				}
			}()

			_, err := c.ExecCommand(context.Background(), []byte("info"))
			if err != nil {
				t.Fatalf("Failed exec command: %s", err)
			}
		},
	)

	t.Run(
		"math.MaxInt32 starting seq wraps to 0",
		func(t *testing.T) {
			cc, sc := net.Pipe()
			defer func() {
				_ = cc.Close()
				_ = sc.Close()
			}()

			c := rcon.NewClient(
				cc,
				rcon.ClientConfig{StartingSeq: math.MaxInt32},
			)

			go func() {
				var req rcon.Packet
				_, err := req.ReadFrom(sc)
				if err != nil {
					t.Fatalf("Failed to read exec command request packet from client: %s", err)
				}

				if req.ID != math.MaxInt32 {
					t.Fatalf("Expected request packet to have ID of math.MaxInt32, got: %d", req.ID)
				}

				resp := rcon.Packet{}
				_, err = resp.WriteTo(sc)
				if err != nil {
					t.Fatalf("Failed to write exec command response packet to client: %s", err)
				}

				_, err = req.ReadFrom(sc)
				if err != nil {
					t.Fatalf("Failed to read exec command request packet from client: %s", err)
				}

				if req.ID != 0 {
					t.Fatalf("Expected request packet to have ID of 0, got: %d", req.ID)
				}

				_, err = resp.WriteTo(sc)
				if err != nil {
					t.Fatalf("Failed to write exec command response packet to client: %s", err)
				}
			}()

			_, err := c.ExecCommand(context.Background(), []byte("info"))
			if err != nil {
				t.Fatalf("Failed exec command: %s", err)
			}

			_, err = c.ExecCommand(context.Background(), []byte("info"))
			if err != nil {
				t.Fatalf("Failed exec command: %s", err)
			}
		},
	)

	t.Run(
		"outbound auth packets are sanitized",
		func(t *testing.T) {
			cc, sc := net.Pipe()
			defer func() {
				_ = cc.Close()
				_ = sc.Close()
			}()

			password := "password"

			c := rcon.NewClient(
				cc,
				rcon.ClientConfig{
					Logger: slog.New(&testLogger{t, password}),
				},
			)

			go func() {
				var req rcon.Packet
				_, err := req.ReadFrom(sc)
				if err != nil {
					t.Fatalf("Failed to read auth request packet from client: %s", err)
				}

				resp := rcon.Packet{
					ID:   0,
					Type: rcon.PacketTypeAuthResponse,
				}
				_, err = resp.WriteTo(sc)
				if err != nil {
					t.Fatalf("Failed to write auth response packet to client: %s", err)
				}
			}()

			err := c.Authorize(context.Background(), password)
			if err != nil {
				t.Fatalf("Failed to authorize: %s", err)
			}
		},
	)
}

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
