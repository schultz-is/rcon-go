package rcon

import (
	"bytes"
	"encoding/hex"
	"math"
	"strconv"
	"testing"
)

func TestPacketMarshalUnmarshalBinary(t *testing.T) {
	ps := []Packet{
		Packet{}, // Empty packet
		Packet{1, PacketTypeAuth, []byte("password")},                                     // Example authorization request
		Packet{2, PacketTypeAuthResponse, nil},                                            // Example successful authorization response
		Packet{-1, PacketTypeAuthResponse, nil},                                           // Example unsuccessful authorization response
		Packet{3, PacketTypeExecCommand, []byte("info")},                                  // Example command request
		Packet{4, PacketTypeResponseValue, []byte("server info goes here")},               // Example command response
		Packet{math.MaxInt32, math.MaxInt32, make([]byte, MaximumPacketSize-WrapperSize)}, // Largest packet allowed, non-standard type field
	}

	for _, p := range ps {
		// Ensure the packet marshals without error.
		b, err := p.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}

		// Ensure MarshalBinary is a pure function.
		b2, err := p.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b, b2) {
			t.Fatalf("Packet.MarshalBinary()[%#v] got two different results: %0x, %0x", p, b, b2)
		}

		// Ensure the resulting bytes unmarshal without error.
		var p2 Packet
		err = p2.UnmarshalBinary(b)
		if err != nil {
			t.Fatal(err)
		}

		// Check that MarshalBinary is the identity function.
		if !p.EqualTo(p2) {
			t.Fatalf("Packet[%#v] != Packet.MarshalBianry()[%#v].UnmarshalBinary()", p, p2)
		}
	}

	// Disallow packets above the maximum packet size defined by the protocol.
	p := Packet{Body: make([]byte, MaximumPacketSize)}
	_, err := p.MarshalBinary()
	if err == nil {
		t.Fatalf("Packet.MarshalBinary()[%#v] succeeded incorrectly", p)
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
		var p Packet
		err = p.UnmarshalBinary(b)
		if err == nil {
			t.Fatalf("Packet.UnmarshalBinary(%0x) succeeded incorrectly", b)
		}
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
		MaximumPacketSize - WrapperSize,
	}

	for _, bodySize := range bodySizes {
		b.Run(
			strconv.Itoa(bodySize),
			func(b *testing.B) {
				for n := 0; n < b.N; n++ {
					p := Packet{
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
