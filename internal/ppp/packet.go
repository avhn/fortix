// Package ppp negotiates an uncompressed IPv4 PPP link over a packet transport.
// It omits authentication, HDLC framing, and protocol/address-field compression.
package ppp

import (
	"encoding/binary"
	"errors"
)

// PPP protocol numbers use their full two-byte representation on every packet.
const (
	ProtocolIPv4 uint16 = 0x0021
	ProtocolLCP  uint16 = 0xc021
	ProtocolIPCP uint16 = 0x8021
	DefaultMRU          = 1354
)

// Control codes are shared by LCP and IPCP; codes above CodeReject are LCP-only.
const (
	ConfigureRequest byte = 1
	ConfigureAck     byte = 2
	ConfigureNak     byte = 3
	ConfigureReject  byte = 4
	TerminateRequest byte = 5
	TerminateAck     byte = 6
	CodeReject       byte = 7
	ProtocolReject   byte = 8
	EchoRequest      byte = 9
	EchoReply        byte = 10
	DiscardRequest   byte = 11
)

// ErrMalformed identifies invalid protocol, control, or option wire encodings.
var ErrMalformed = errors.New("malformed PPP packet")

// Control is one decoded control packet. Data excludes the four-byte header and
// borrows the decoder input; callers retaining it must copy it.
type Control struct {
	Code byte
	ID   byte
	Data []byte
}

// Option is one length-delimited configuration option. Data borrows the original
// packet; Type and Data together preserve the byte-identical wire representation.
type Option struct {
	Type byte
	Data []byte
}

// DecodeControl decodes an information field bounded by DefaultMRU. PPP padding
// after the declared length is ignored; truncated or invalid lengths are errors.
func DecodeControl(data []byte) (Control, error) {
	if len(data) < 4 || len(data) > DefaultMRU {
		return Control{}, ErrMalformed
	}
	n := int(binary.BigEndian.Uint16(data[2:4]))
	if n < 4 || n > len(data) {
		return Control{}, ErrMalformed
	}
	return Control{Code: data[0], ID: data[1], Data: data[4:n]}, nil
}

// DecodeOptions validates all option lengths before returning ordered views.
// Duplicate options and oversized lists are rejected to avoid ambiguous updates.
func DecodeOptions(data []byte) ([]Option, error) {
	if len(data) > DefaultMRU-4 {
		return nil, ErrMalformed
	}
	options := make([]Option, 0, len(data)/2)
	var seen [256]bool
	for len(data) > 0 {
		if len(data) < 2 || int(data[1]) < 2 || int(data[1]) > len(data) || seen[data[0]] {
			return nil, ErrMalformed
		}
		n := int(data[1])
		seen[data[0]] = true
		options = append(options, Option{Type: data[0], Data: data[2:n]})
		data = data[n:]
	}
	return options, nil
}

// controlPacket encodes one full-protocol control packet from bounded internal data.
func controlPacket(protocol uint16, code, id byte, data []byte) []byte {
	packet := make([]byte, 6+len(data))
	binary.BigEndian.PutUint16(packet[:2], protocol)
	packet[2], packet[3] = code, id
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(data)+4))
	copy(packet[6:], data)
	return packet
}

// optionBytes preserves the exact encoding of an already validated option.
func optionBytes(option Option) []byte {
	return append([]byte{option.Type, byte(len(option.Data) + 2)}, option.Data...)
}

// uint32Option encodes a four-byte address or magic number configuration option.
func uint32Option(kind byte, value uint32) []byte {
	return []byte{kind, 6, byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}
}
