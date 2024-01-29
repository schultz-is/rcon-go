package rcon

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultClientTimeout is the default time allowed for a client to both connect to an RCON server
// and to perform a request/response round trip.
const DefaultClientTimeout = 15 * time.Second

// Client is an RCON client that manages a single connection to an RCON server. Client instances
// are safe for concurrent use, but should be pooled in cases of high-throughput to avoid
// contention. The RCON protocol does not specify any keep alive functionality, so a Client may
// return an EOF if unused for an extended period.
type Client struct {
	// The seq field tracks the monotonically increasing packet ID that a Client sends to servers in
	// a request. This will be a positive value between zero and [math.MaxInt32] inclusive.
	seq atomic.Int32

	// The mu field controls access to the underlying TCP connection of a Client.
	mu sync.Mutex

	// The conn field is the TCP transport used by a Client instance to communicate with an RCON
	// server.
	conn net.Conn

	// timeout limits the amount of time a Client can spend connecting to an RCON server and the
	// amount of time a Client can spend performing a request/response round trip. When this is zero,
	// the default client timeout will be used.
	timeout time.Duration

	// logger is a [slog.Logger] that a Client instance writes log messages to. When the logger is
	// nil, log operations are essentially NOPs.
	logger *slog.Logger

	// logOutboundAuthPackets is a flag that must be explicitly enabled when the client is created.
	// This field enables debug logging to include outbound authorization request packets, exposing
	// server passwords in plaintext. Only enable this flag if you are aware of the implications and
	// are willing to accept the risks!
	logOutboundAuthPackets bool
}

// NewClient creates and returns a Client which is connected to the provided addr.
func NewClient(addr string) (*Client, error) {
	return NewClientWithConfig(addr, ClientConfig{})
}

// NewClientWithConfig creates and returns a Client which is connected to the provided addr using
// the provided [ClientConfig].
func NewClientWithConfig(addr string, config ClientConfig) (*Client, error) {
	// Set the timeout for dialing and requests based on the provided config, falling back on the
	// default value.
	timeout := config.Timeout
	if timeout == 0 {
		timeout = DefaultClientTimeout
	}

	// Opent the TCP connection to the RCON server.
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}

	c := &Client{
		conn:                   conn,
		timeout:                timeout,
		logger:                 config.Logger,
		logOutboundAuthPackets: config.LogOutboundAuthPackets,
	}

	return c, nil
}

// Request sends the provided [Packet] to the RCON server and returns a response [Packet] provided
// by the RCON server. When the client is unauthorized, an error is returned alongside the response
// packet.
func (c *Client) Request(ctx context.Context, req Packet) (*Packet, error) {
	type result struct {
		packet *Packet
		err    error
	}

	timeout := c.timeout
	if timeout == 0 {
		timeout = DefaultClientTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch := make(chan result)
	defer close(ch)

	c.mu.Lock()
	defer c.mu.Unlock()

	go func() {
		// If debug logging is enabled, log out the packet hex. Only include outbound authorization
		// packets when the
		if c.debugEnabled(ctx) {
			// Skip outgoing authorization packets which include the server password in plaintext.
			switch {
			case req.Type == PacketTypeAuth && !c.logOutboundAuthPackets:
				break
			default:
				bs, err := req.MarshalBinary()
				if err != nil {
					ch <- result{nil, err}
					return
				}
				c.debug(ctx, "sent request packet", "hex", hex.EncodeToString(bs))
			}
		}

		_, err := req.WriteTo(c.conn)
		if err != nil {
			ch <- result{nil, err}
			return
		}

		var resp Packet
		_, err = resp.ReadFrom(c.conn)
		if err != nil {
			ch <- result{nil, err}
			return
		}

		if c.debugEnabled(ctx) {
			bs, err := resp.MarshalBinary()
			if err != nil {
				ch <- result{nil, err}
				return
			}
			c.debug(ctx, "received response packet", "hex", hex.EncodeToString(bs))
		}

		// Handle authorization errors.
		if resp.Type == PacketTypeAuthResponse && resp.ID == -1 {
			c.err(ctx, "server returned authorization failure")
			ch <- result{&resp, errors.New("rcon: unauthorized")}
			return
		}

		ch <- result{&resp, nil}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		return res.packet, res.err
	}
}

// Authorize sends the provided password to the connected RCON server.
func (c *Client) Authorize(ctx context.Context, password string) error {
	req := Packet{
		ID:   c.incrementSeq(),
		Type: PacketTypeAuth,
		Body: []byte(password),
	}
	_, err := c.Request(ctx, req)
	if err != nil {
		return err
	}

	return nil
}

// ExecCommand sends the provided command bytes to the server and returns the resulting bytes.
func (c *Client) ExecCommand(ctx context.Context, cmd []byte) ([]byte, error) {
	req := Packet{
		ID:   c.incrementSeq(),
		Type: PacketTypeExecCommand,
		Body: cmd,
	}

	resp, err := c.Request(ctx, req)
	if err != nil {
		return nil, err
	}

	return resp.Body, nil
}

// incrementSeq increments and then returns the seq field of the receiving Client. This is done
// independently of the lock held on the underlying TCP connection. When the value of seq reaches
// [math.MaxInt32], the value wraps back around to 0.
func (c *Client) incrementSeq() int32 {
	swapped := false
	for !swapped {
		seq := c.seq.Load()
		if seq == math.MaxInt32 {
			swapped = c.seq.CompareAndSwap(seq, 0)
		} else {
			swapped = c.seq.CompareAndSwap(seq, seq+1)
		}
	}
	return c.seq.Load()
}

// debugEnabled returns whether the receiving Client logger is level set for debug output. This can
// change based on values in the context, which is why the request context is a parameter.
func (c *Client) debugEnabled(ctx context.Context) bool {
	if c.logger == nil {
		return false
	}
	return c.logger.Handler().Enabled(ctx, slog.LevelDebug)
}

// log sends the provided structured log message to the receiving Client's underlying logger. When
// the logger is nil, this method is essentially a NOP.
func (c *Client) log(ctx context.Context, level slog.Level, msg string, args ...any) {
	if c.logger != nil {
		c.logger.Log(ctx, level, msg, args...)
	}
}

// debug writes the provided structured debug message to the receiving Client's underlying logger.
// When the logger is nil, this method is essentially a NOP.
func (c *Client) debug(ctx context.Context, msg string, args ...any) {
	c.log(ctx, slog.LevelDebug, msg, args...)
}

// info writes the provided structured info message to the receiving Client's underlying logger.
// When the logger is nil, this method is essentially a NOP.
func (c *Client) info(ctx context.Context, msg string, args ...any) {
	c.log(ctx, slog.LevelInfo, msg, args...)
}

// warn writes the provided structured warn message to the receiving Client's underlying logger.
// When the logger is nil, this method is essentially a NOP.
func (c *Client) warn(ctx context.Context, msg string, args ...any) {
	c.log(ctx, slog.LevelWarn, msg, args...)
}

// err writes the provided structured error message to the receiving Client's underlying logger.
// When the logger is nil, this method is essentially a NOP.
func (c *Client) err(ctx context.Context, msg string, args ...any) {
	c.log(ctx, slog.LevelError, msg, args...)
}

// ClientConfig contains settings to control [Client] instances.
type ClientConfig struct {
	// Timeout controls both of the TCP dial timeout and the overall timeout for any given request.
	Timeout time.Duration

	// Logger is a [slog.Logger] which a [Client] will write log entries to.
	Logger *slog.Logger

	// LogOutboundAuthPackets enables the output of outbound authorization packets which include the
	// server authorization password.
	//
	// WARNING: Enabling this setting will expose server passwords in plain text. Only enable this
	// if you understand the implications and are willing to accept the risks!
	LogOutboundAuthPackets bool
}
