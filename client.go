// Copyright 2024 Matt Schultz <schultz@sent.com>. All rights reserved.
// Use of this source code is governed by an ISC license that can be found in the LICENSE file.

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

// DefaultClientTimeout is the default amount of time allowed for a client to make a request and
// response round trip.
const DefaultClientTimeout = 15 * time.Second

// Client is an RCON client that manages a single connection to an RCON server. While the RCON
// protocol specifies transport over TCP, this client allows transport over anything that satisfies
// the [net.Conn] interface. There are a few reasons this might be useful to a consumer of this
// package:
//  1. RCON is unencrypted by default, which means the authorization password is written over the
//     wire in plain test. The [crypto/tls.Conn] satisfies the [net.Conn] interface and can be
//     supplied to this client to encrypt RCON traffic seamlessly. This is of course only possible
//     when the RCON server is also using TLS.
//  2. In the case the RCON server and client are running on the same machine, it may be useful to
//     communicate over a Unix socket (or other IPC communication transport,) rather than a full
//     TCP socket.
//  3. Providing a [net.Conn] that the caller controls allows for logging, debugging, and
//     packet modification outside the scope of the client.
//
// Clients are safe for concurrent use, but should likely be pooled to avoid contention in
// high-throughput scenarios.
//
// RCON does not specify any keep alive functionality, so a client may return an EOF or similar
// error when idle for an extended period.
type Client struct {
	// seq tracks the monotonically increasing packet ID that a client sends to servers with each
	// request. This will be a positive value between zero and [math.MaxInt32] inclusive.
	seq atomic.Int32

	// mu controls concurrent access to the underlying connection.
	mu sync.Mutex

	// conn is the underlying connection RCON messages are sent and received over.
	conn net.Conn

	// timeout is a limit on the time allowed for a client to perform a request and response round
	// trip.
	timeout time.Duration

	// logger receives any log output from a client.
	logger *slog.Logger

	// logOutboundAuthPackets is a flag that must be explicitly enabled when the client is created.
	// This field enables debug logging to include outbound authorization request packets, exposing
	// server passwords in plaintext. When this field is false (the default value,) outbound
	// authorization packets will be sanitized to hide both the password text and packet length.
	//
	// WARNING: Only enable this flag if you are aware of the implications and are willing to accept
	// the risks!
	logOutboundAuthPackets bool
}

// NewClient creates and returns a [Client] that uses conn as its transport, configured by the
// provided config.
//
// Once a conn is provided to a NewClient call, the conn should not be used outside of the client
// in order to ensure reliable message delivery.
func NewClient(conn net.Conn, config ClientConfig) *Client {
	c := &Client{
		conn:                   conn,
		timeout:                config.Timeout,
		logger:                 config.Logger,
		logOutboundAuthPackets: config.LogOutboundAuthPackets,
	}
	c.seq.Store(config.StartingSeq)
	return c
}

// Close simple closes the receiving client's underlying connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.conn.Close()
}

// Request sends the provided [Packet] to the RCON server and returns a response [Packet] and/or an
// error. When the client receives an authorization error packet in response, it is returned
// alongside [ErrUnauthorized].
func (c *Client) Request(ctx context.Context, req Packet) (*Packet, error) {
	// Specify a result type to communicate the response over the channel.
	type result struct {
		packet *Packet
		err    error
	}

	// Configure the context with the client's configured timeout, falling back on the default.
	timeout := c.timeout
	if timeout == 0 {
		timeout = DefaultClientTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch := make(chan result)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Perform the actual request in a goroutine to support timing out.
	go func() {
		defer close(ch)

		c.logPacket(ctx, "sending packet", req)
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
		c.logPacket(ctx, "received packet", resp)

		// Check for an authorization error.
		if resp.Type == PacketTypeAuthResponse && resp.ID == -1 {
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

// Authorize sends the provided password to the RCON server to authorize the current session.
func (c *Client) Authorize(ctx context.Context, password string) error {
	req := Packet{
		ID:   c.loadAndIncrementSeq(),
		Type: PacketTypeAuth,
		Body: []byte(password),
	}
	_, err := c.Request(ctx, req)
	return err
}

// ExecCommand sends the provided bytes as a command to the server and returns the response body.
func (c *Client) ExecCommand(ctx context.Context, cmd []byte) ([]byte, error) {
	req := Packet{
		ID:   c.loadAndIncrementSeq(),
		Type: PacketTypeExecCommand,
		Body: cmd,
	}
	resp, err := c.Request(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// loadAndIncrementSeq returns and then increments the receiving client's seq, wrapping around to
// zero when [math.MaxInt32] is reached.
func (c *Client) loadAndIncrementSeq() int32 {
	var seq int32
	swapped := false
	for !swapped {
		seq = c.seq.Load()
		switch {
		case seq < 0:
			swapped = c.seq.CompareAndSwap(seq, 1)
			seq = 0

		case seq == math.MaxInt32:
			swapped = c.seq.CompareAndSwap(seq, 0)

		default:
			swapped = c.seq.CompareAndSwap(seq, seq+1)
		}
	}
	return seq
}

// logPacket sends a log record containing the provided log message and packet to the client's
// logger for handling. When the logger is nil or is not level set for debug records, this function
// is essentially a NOP. If the provided packet is an outbound authorization packet, its body and
// length are obfuscated to prevent leaking a plaintext password into logs.
func (c *Client) logPacket(ctx context.Context, logMsg string, packet Packet) {
	// NOP if the client logger is nil or is not level set for debug log messages.
	if c.logger == nil || !c.logger.Handler().Enabled(ctx, slog.LevelDebug) {
		return
	}

	// Unless the client is explicitly configured to log outbound authorization packets, scrub the
	// password when applicable.
	if packet.Type == PacketTypeAuth && !c.logOutboundAuthPackets {
		packet.Body = []byte{'x', 'x', 'x', 'x', 'x'}
	}

	bs, err := packet.MarshalBinary()
	if err != nil {
		c.logger.LogAttrs(ctx, slog.LevelError, "failed to marshal packet for logging", slog.String("error", err.Error()))
		return
	}

	c.logger.LogAttrs(ctx, slog.LevelDebug, logMsg, slog.String("packet", hex.EncodeToString(bs)))
}

// ClientConfig contains settings to control [Client] instances.
type ClientConfig struct {
	// Timeout limits the amount of time a client can spend performing a request and response round
	// trip. A value of zero will inform the client to use the [DefaultClientTimeout].
	Timeout time.Duration

	// StartingSeq is the initial value for a client's packet ID sequence. Any value less than zero
	// will be ignored.
	StartingSeq int32

	// Logger receives log entries from a client.
	Logger *slog.Logger

	// LogOutboundAuthPackets is a flag that must be explicitly enabled when the client is created.
	// This field enables debug logging to include outbound authorization request packets, exposing
	// server passwords in plaintext. When this field is false (the default value,) outbound
	// authorization packets will be sanitized to hide both the password text and packet length.
	//
	// WARNING: Only enable this flag if you are aware of the implications and are willing to accept
	// the risks!
	LogOutboundAuthPackets bool
}
