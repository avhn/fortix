package native

import (
	"encoding/binary"
	"errors"
	"io"
)

// FrameHeaderSize is the total-length, magic, payload-length header size in bytes.
const FrameHeaderSize = 6

// MaxFramePayload bounds allocation to the largest payload representable by the
// protocol's unsigned sixteen-bit total length. PPP negotiates a smaller MRU later.
const MaxFramePayload = 65535 - FrameHeaderSize

// ErrInvalidFrame identifies inconsistent lengths, an incorrect marker, or an empty
// payload. Short headers and payloads instead preserve io.EOF or io.ErrUnexpectedEOF.
var ErrInvalidFrame = errors.New("invalid gateway tunnel frame")

// ReadFrame reads exactly one six-byte-header PPP frame from reader. It handles
// fragmented reads without consuming the following coalesced frame, validates lengths
// before allocating, and returns the payload or a framing/underlying read error.
func ReadFrame(reader io.Reader) ([]byte, error) {
	var header [FrameHeaderSize]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	total := int(binary.BigEndian.Uint16(header[0:2]))
	length := int(binary.BigEndian.Uint16(header[4:6]))
	if binary.BigEndian.Uint16(header[2:4]) != 0x5050 || length == 0 || length > MaxFramePayload || total != length+FrameHeaderSize {
		return nil, ErrInvalidFrame
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// WriteFrame writes one bounded PPP payload to writer, returning invalid-size or
// underlying write errors. Callers must serialize writers sharing one connection.
// A short write is rejected rather than silently producing an incomplete frame.
func WriteFrame(writer io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > MaxFramePayload {
		return ErrInvalidFrame
	}
	var header [FrameHeaderSize]byte
	binary.BigEndian.PutUint16(header[0:2], uint16(len(payload)+FrameHeaderSize))
	binary.BigEndian.PutUint16(header[2:4], 0x5050)
	binary.BigEndian.PutUint16(header[4:6], uint16(len(payload)))
	if err := writeFull(writer, header[:]); err != nil {
		return err
	}
	return writeFull(writer, payload)
}

// writeFull preserves writer errors and detects short successful writes.
func writeFull(writer io.Writer, data []byte) error {
	n, err := writer.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}
