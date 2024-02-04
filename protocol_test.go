// Copyright 2024 Matt Schultz <schultz@sent.com>. All rights reserved.
// Use of this source code is governed by an ISC license that can be found in the LICENSE file.

package rcon_test

import (
	"bytes"
	"encoding/hex"
	"math"
	"strconv"
	"testing"

	"github.com/schultz-is/rcon-go"
)

func TestPacketBinaryFormatting(t *testing.T) {
	ps := []rcon.Packet{
		rcon.Packet{}, // Empty packet
		rcon.Packet{1, rcon.PacketTypeAuth, []byte("password")},                                          // Example authorization request
		rcon.Packet{2, rcon.PacketTypeAuthResponse, nil},                                                 // Example successful authorization response
		rcon.Packet{-1, rcon.PacketTypeAuthResponse, nil},                                                // Example unsuccessful authorization response
		rcon.Packet{3, rcon.PacketTypeExecCommand, []byte("info")},                                       // Example command request
		rcon.Packet{4, rcon.PacketTypeResponseValue, []byte("server info goes here")},                    // Example command response
		rcon.Packet{math.MaxInt32, math.MaxInt32, make([]byte, rcon.MaximumPacketSize-rcon.WrapperSize)}, // Largest packet allowed, non-standard type field
	}

	for _, p := range ps {
		b, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("Packet[%#v].MarshalBinary() failed unexpectedly: %s", p, err)
		}

		var buf bytes.Buffer
		n, err := p.WriteTo(&buf)
		if err != nil {
			t.Fatalf("Packet[%#v].WriteTo() failed unexpectedly: %s", p, err)
		}

		// Ensure MarshalBinary is a pure function.
		b2, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("Packet[%#v].MarshalBinary() failed unexpectedly: %s", p, err)
		}
		if !bytes.Equal(b, b2) {
			t.Fatalf("Packet[%#v].MarshalBinary() got two different results: %0x, %0x", p, b, b2)
		}

		// Ensure WriteTo is a pure function.
		var buf2 bytes.Buffer
		n2, err := p.WriteTo(&buf2)
		if err != nil {
			t.Fatalf("Packet[%#v].WriteTo() failed unexpectedly: %s", p, err)
		}
		if n != n2 || !bytes.Equal(buf.Bytes(), buf2.Bytes()) {
			t.Fatalf("Packet[%#v].WriteTo() got two different results: %0x, %0x", p, buf.Bytes(), buf2.Bytes())
		}

		var p2 rcon.Packet
		err = p2.UnmarshalBinary(b)
		if err != nil {
			t.Fatalf("Packet.UnmarshalBinary(%0x) failed unexpectedly: %s", b, err)
		}

		var p3 rcon.Packet
		n3, err := p3.ReadFrom(&buf)
		if err != nil {
			t.Fatalf("Packet.ReadFrom(%0x) failed unexpectedly: %s", buf.Bytes(), err)
		}

		// Check that MarshalBinary is the identity function.
		if !p.EqualTo(p2) {
			t.Fatalf("Packet[%#v].MarshalBinary() is not the identity function, got: %#v", p, p2)
		}

		// Ensure WriteTo is the identity function.
		if n != n3 || !p.EqualTo(p3) {
			t.Fatalf("Packet[%#v].WriteTo() is not the identity function, got: %#v", p, p3)
		}
	}

	// Disallow packets above the maximum packet size defined by the protocol.
	p := rcon.Packet{Body: make([]byte, rcon.MaximumPacketSize)}
	_, err := p.MarshalBinary()
	if err == nil {
		t.Fatalf("Packet[%#v].MarshalBinary() succeeded incorrectly", p)
	}

	bss := []string{
		"d6ffffff",                             // Negative packet size
		"09000000",                             // Packet size smaller than allowed by protocol
		"01100000",                             // Packet size larger than allowed by protocol
		"0a00000011",                           // Packet shorter than provided size
		"0a0000001111111122222222333333330000", // Packet longer than provided size
		"0a00000011111111222222223333",         // Missing double null byte termination
	}

	for _, bs := range bss {
		b, err := hex.DecodeString(bs)
		if err != nil {
			t.Fatalf("invalid hex string in test table: %0x, %s", bs, err)
		}

		// Expect the unmarshal to fail.
		var p rcon.Packet
		err = p.UnmarshalBinary(b)
		if err == nil {
			t.Fatalf("Packet.UnmarshalBinary(%0x) succeeded incorrectly", b)
		}
	}
}

func TestPacketEqualTo(t *testing.T) {
	p := rcon.Packet{}
	if !p.EqualTo(p) {
		t.Fatalf("Packet[%#v].EqualTo(%#v) returned false when comparing a packet to itself", p, p)
	}

	p = rcon.Packet{
		ID:   12345,
		Type: rcon.PacketTypeResponseValue,
		Body: []byte("some command response value goes here..."),
	}
	if !p.EqualTo(p) {
		t.Fatalf("Packet[%#v].EqualTo(%#v) returned false when comparing a packet to itself", p, p)
	}

	p2 := p.Clone()
	if !p.EqualTo(p2) {
		t.Fatalf("Packet[%#v].EqualTo(%#v) returned false when comparing a packet to a clone of itself", p, p2)
	}

	p2.ID = p.ID - 1
	if p.EqualTo(p2) {
		t.Fatalf("Packet[%#v].EqualTo(%#v) incorrectly returned true for different IDs", p, p2)
	}

	p2.ID = p.ID
	p2.Type = p.Type + 1
	if p.EqualTo(p2) {
		t.Fatalf("Packet[%#v].EqualTo(%#v) incorrectly returned true for different types", p, p2)
	}

	p2.Type = p.Type
	p2.Body = append(p.Body, 'X')
	if p.EqualTo(p2) {
		t.Fatalf("Packet[%#v].EqualTo(%#v) incorrectly returned true for different bodies", p, p2)
	}
}

func BenchmarkMarshalBinary(b *testing.B) {
	bodySizes := []int{
		0,
		5,
		10,
		15,
		25,
		125,
		250,
		500,
		1000,
		2000,
		rcon.MaximumPacketSize - rcon.WrapperSize,
	}

	for _, bodySize := range bodySizes {
		b.Run(
			strconv.Itoa(bodySize),
			func(b *testing.B) {
				for n := 0; n < b.N; n++ {
					p := rcon.Packet{
						Body: make([]byte, bodySize),
					}
					bs, err := p.MarshalBinary()
					if err != nil {
						b.Fatal(err)
					}
					b.SetBytes(int64(len(bs)))
				}
			},
		)
	}
}
