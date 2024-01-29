package rcon

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// WrapperSize is the cumulative size of non-body bytes that contribute to calculation of the packet
// size that precedes a binary packet. Eight bytes are accounted for by the packet ID and type,
// while two bytes are accounted for by the null byte termination of the body and packet. The packet
// size itself is not included in the size calculation.
const WrapperSize = 8 + 2

// MaximumPacketSize is the largest value allowed for the packet size taht precedes binary packets.
// This value is outlined in the protocol.
const MaximumPacketSize = 4096

const (
	// PacketTypeAuth represents a client authorization request packet. It indicates that the body
	// will contain the server password.
	PacketTypeAuth = 3

	// PacketTypeAuthResponse represents a server authorization response packet. If authorization
	// failed, the packet ID will have a value of -1 rather than that of the matching client request
	// packet.
	PacketTypeAuthResponse = 2

	// PacketTypeExecCommand represents a client request packet that contains a command to be executed
	// by the server.
	PacketTypeExecCommand = 2

	// PacketTypeResponseValue represents a server repsonse packet that contains the output of a
	// server command initiated by a [PacketTypeExecCommand] client request packet.
	PacketTypeResponseValue = 0
)

// Packet is a singular RCON protocol packet, either as a request from a client or a response from
// a server.
type Packet struct {
	// ID is a field chosen by the client which can be used to correlate request packets with
	// response packets. It need not be unique, but uniqueness allows for the aforementioned packet
	// correlation. The singular case where this response field will not match the request packet is
	// in the case of auth failure, where the [Packet.Type] will be an [PacketTypeAuthResponse] and
	// this field will have a value of -1. In every other case this field should be a positive
	// integer.
	ID int32

	// Type indicates the purpose of the packet. Its value should always be one of [PacketTypeAuth],
	// [PacketTypeAuthResponse], [PacketTypeExecCommand], or [PacketTypeResponseValue].
	Type int32

	// Body contains the data relevant to the provided packet type. This will be the RCON password for
	// the server, the command to be executed, or the server's response to a request. It's possible
	// that the body is empty.
	Body []byte
}

// MarshalBinary encodes the receiving [Packet] into binary form and returns the result. This
// satisfies the [io.BinaryMarshaler] interface.
func (p Packet) MarshalBinary() ([]byte, error) {
	// Ensure the packet confoms to the maximum size defined in the protocol.
	packetSize := int32(len(p.Body) + WrapperSize)
	if packetSize > MaximumPacketSize {
		return nil, errors.New("rcon: packet too large")
	}

	// Create an appropriately sized byte buffer and write the binary encoded packet.
	b := bytes.NewBuffer(make([]byte, packetSize+4))
	b.Reset()
	err := binary.Write(b, binary.LittleEndian, packetSize)
	if err != nil {
		return nil, err
	}
	err = binary.Write(b, binary.LittleEndian, p.ID)
	if err != nil {
		return nil, err
	}
	err = binary.Write(b, binary.LittleEndian, p.Type)
	if err != nil {
		return nil, err
	}
	_, err = b.Write(p.Body)
	if err != nil {
		return nil, err
	}
	_, err = b.Write([]byte{0, 0})
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// WriteTo writes a binary representation of the packet to [io.Writer] w. This method satisfies the
// [io.WriterTo] interface.
func (p Packet) WriteTo(w io.Writer) (int64, error) {
	bs, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(bs)

	return int64(n), err
}

// UnmarshalBinary decodes the binary encoded packet b into the receiving [Packet]. This satisfies
// the [io.BinaryUnmarshaler] interface.
func (p *Packet) UnmarshalBinary(b []byte) error {
	r := bytes.NewReader(b)
	_, err := p.ReadFrom(r)
	if err != nil {
		return err
	}
	return nil
}

// ReadFrom reads a binary representation of a packet into the receiving [Packet] instance. This
// method satisfies the [io.ReaderFrom] interface.
func (p *Packet) ReadFrom(r io.Reader) (int64, error) {
	// Keep track of bytes read.
	n := int64(0)

	// Read the provided packet size.
	packetSize := int32(0)
	err := binary.Read(r, binary.LittleEndian, &packetSize)
	if err != nil {
		return n, err
	}
	n += 4

	// Ensure the packet size isn't smaller than allowed by the protocol.
	if packetSize < WrapperSize {
		return n, errors.New("rcon: packet too small")
	}

	// Ensure the packet size isn't larger than allowed by the protocol.
	if packetSize > MaximumPacketSize {
		return n, errors.New("rcon: packet too large")
	}

	err = binary.Read(r, binary.LittleEndian, &(p.ID))
	if err != nil {
		return n, err
	}
	n += 4

	err = binary.Read(r, binary.LittleEndian, &(p.Type))
	if err != nil {
		return n, err
	}
	n += 4

	p.Body = make([]byte, packetSize-WrapperSize)
	if _, err := r.Read(p.Body); err != nil {
		return n, err
	}
	n += int64(packetSize - WrapperSize)

	// Ensure the packet is properly terminated by two zero bytes.
	z := make([]byte, 2)
	if _, err := r.Read(z); err != nil {
		return n, err
	}
	n += 2
	if z[0] != 0 || z[1] != 0 {
		return n, errors.New("rcon: packet incorrectly terminated")
	}

	return n, nil
}

// EqualTo determines if the provided Packet content matches the receiving Packet content.
func (p Packet) EqualTo(p2 Packet) bool {
	switch {
	case p.ID != p2.ID:
		return false
	case p.Type != p2.Type:
		return false
	case !bytes.Equal(p.Body, p2.Body):
		return false
	}
	return true
}
