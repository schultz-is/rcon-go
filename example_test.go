// Copyright 2024 Matt Schultz <schultz@sent.com>. All rights reserved.
// Use of this source code is governed by an ISC license that can be found in the LICENSE file.

package rcon_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"

	"github.com/schultz-is/rcon-go"
)

func ExamplePacket_WriteTo() {
	var buf bytes.Buffer

	p := rcon.Packet{
		ID:   42,
		Type: rcon.PacketTypeExecCommand,
		Body: []byte("info"),
	}
	n, err := p.WriteTo(&buf)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Wrote %d bytes: %0x\n", n, buf.Bytes())

	// Output:
	// Wrote 18 bytes: 0e0000002a00000002000000696e666f0000
}

func ExamplePacket_ReadFrom() {
	bs, err := hex.DecodeString("0e0000002a00000002000000696e666f0000")
	if err != nil {
		log.Fatal(err)
	}
	rdr := bytes.NewReader(bs)

	var p rcon.Packet
	n, err := p.ReadFrom(rdr)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Read %d bytes: %#v\n", n, p)

	// Output:
	// Read 18 bytes: rcon.Packet{ID:42, Type:2, Body:[]uint8{0x69, 0x6e, 0x66, 0x6f}}
}

func ExampleClient_Authorize() {
	// Client is a BYOC (bring your own conn) implementation.
	conn, err := net.Dial("tcp", "192.0.2.1:27015")
	if err != nil {
		log.Fatal(err)
	}

	c := rcon.NewClient(conn, rcon.ClientConfig{})
	defer c.Close()

	err = c.Authorize(context.Background(), "super secret password")
	if err != nil {
		log.Fatal(err)
	}
}

func ExampleClient_ExecCommand() {
	// Client is a BYOC (bring your own conn) implementation.
	conn, err := net.Dial("tcp", "192.0.2.1:27015")
	if err != nil {
		log.Fatal(err)
	}

	c := rcon.NewClient(conn, rcon.ClientConfig{})
	defer c.Close()

	result, err := c.ExecCommand(context.Background(), []byte("ping"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("ExecCommand result: %q\n", string(result))

	// Output:
	// ExecCommand result: "pong"
}

func ExampleClient_Request() {
	// Client is a BYOC (bring your own conn) implementation.
	conn, err := net.Dial("tcp", "192.0.2.1:27015")
	if err != nil {
		log.Fatal(err)
	}

	c := rcon.NewClient(conn, rcon.ClientConfig{})
	defer c.Close()

	req := rcon.Packet{
		ID:   42,
		Type: rcon.PacketTypeExecCommand,
		Body: []byte("ping"),
	}
	resp, err := c.Request(context.Background(), req)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Request result: %#v\n", resp)

	// Output:
	// Request result: rcon.Packet{ID:42, Type:0, Body:[]uint8{0x70, 0x6f, 0x6e, 0x67}}
}
