package tun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// TestFamilyPrefix checks network byte order, both IP families, and malformed
// headers without opening a privileged tunnel device.
func TestFamilyPrefix(t *testing.T) {
	for _, version := range []byte{4, 6} {
		packet := []byte{version << 4, 1, 2, 3}
		frame := make([]byte, familyPrefixSize+len(packet))
		putFamilyPrefix(frame, packet)
		copy(frame[familyPrefixSize:], packet)
		wantFamily := uint32(utunIPv4)
		if version == 6 {
			wantFamily = utunIPv6
		}
		if got := binary.BigEndian.Uint32(frame[:familyPrefixSize]); got != wantFamily {
			t.Fatalf("family = %d, want %d", got, wantFamily)
		}
		got, err := stripFamilyPrefix(frame)
		if err != nil || !bytes.Equal(got, packet) {
			t.Fatalf("decoded = %x, %v, want %x", got, err, packet)
		}
	}
	for _, frame := range [][]byte{
		nil, {0}, {0, 0, 0}, {0, 0, 0, utunIPv4},
		{0, 0, 0, utunIPv4, 0x60}, {0, 0, 0, utunIPv6, 0x45},
		{0, 0, 0, 99, 0x45}, {utunIPv4, 0, 0, 0, 0x45},
		{0, 0, 0, utunIPv4, 0},
	} {
		if _, err := stripFamilyPrefix(frame); !errors.Is(err, ErrInvalidPacket) {
			t.Fatalf("frame %x error = %v, want invalid packet", frame, err)
		}
	}
}

// TestPacketValidation checks MTU bounds before copying and supports only IPv4
// and IPv6 framing, without pretending to validate the complete IP header.
func TestPacketValidation(t *testing.T) {
	for _, tc := range []struct {
		packet []byte
		mtu    int
		want   error
	}{
		{nil, 10, ErrInvalidPacket}, {[]byte{0x30}, 10, ErrInvalidPacket},
		{[]byte{0x45}, 1, nil}, {[]byte{0x60}, 1, nil},
		{[]byte{0x45, 0}, 1, ErrPacketTooLarge},
	} {
		if err := validatePacket(tc.packet, tc.mtu); !errors.Is(err, tc.want) {
			t.Errorf("validate %x mtu %d = %v, want %v", tc.packet, tc.mtu, err, tc.want)
		}
	}
}

// FuzzFamilyPrefix exercises arbitrary utun datagrams and verifies that every
// accepted frame round-trips to the exact family prefix and packet bytes.
func FuzzFamilyPrefix(f *testing.F) {
	for _, frame := range [][]byte{
		nil, {0, 0, 0, utunIPv4, 0x45}, {0, 0, 0, utunIPv6, 0x60},
		{0, 0, 0, utunIPv6, 0x45},
	} {
		f.Add(frame)
	}
	f.Fuzz(func(t *testing.T, frame []byte) {
		packet, err := stripFamilyPrefix(frame)
		if err != nil {
			if !errors.Is(err, ErrInvalidPacket) {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}
		if len(packet) != len(frame)-familyPrefixSize || len(packet) == 0 {
			t.Fatal("accepted invalid payload length")
		}
		var header [familyPrefixSize]byte
		putFamilyPrefix(header[:], packet)
		if !bytes.Equal(header[:], frame[:familyPrefixSize]) || !bytes.Equal(packet, frame[familyPrefixSize:]) {
			t.Fatal("accepted frame did not round-trip")
		}
	})
}
