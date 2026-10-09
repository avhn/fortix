package tun

import "encoding/binary"

// Darwin utun uses a four-byte network-order address family, not an IP version.
const (
	familyPrefixSize = 4
	utunIPv4         = 2
	utunIPv6         = 30
)

// validatePacket checks the supported IP versions and MTU before packet copying.
// Header contents are left to the IP stack; only framing is validated here.
func validatePacket(packet []byte, mtu int) error {
	if len(packet) > mtu {
		return ErrPacketTooLarge
	}
	if len(packet) == 0 || (packet[0]>>4 != 4 && packet[0]>>4 != 6) {
		return ErrInvalidPacket
	}
	return nil
}

// putFamilyPrefix writes the Darwin family for a previously validated packet.
// frame must contain at least four bytes; packet must be nonempty IPv4 or IPv6.
func putFamilyPrefix(frame, packet []byte) {
	family := uint32(utunIPv4)
	if packet[0]>>4 == 6 {
		family = utunIPv6
	}
	binary.BigEndian.PutUint32(frame[:familyPrefixSize], family)
}

// stripFamilyPrefix borrows the payload of a Darwin frame after checking its
// header and IP version agree. Short or unsupported frames return an error.
func stripFamilyPrefix(frame []byte) ([]byte, error) {
	if len(frame) <= familyPrefixSize {
		return nil, ErrInvalidPacket
	}
	packet := frame[familyPrefixSize:]
	family := binary.BigEndian.Uint32(frame[:familyPrefixSize])
	if (family == utunIPv4 && packet[0]>>4 == 4) || (family == utunIPv6 && packet[0]>>4 == 6) {
		return packet, nil
	}
	return nil, ErrInvalidPacket
}
