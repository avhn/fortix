package native

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// byteReader fragments reads to verify framing does not depend on TLS record sizes.
type byteReader struct{ io.Reader }

// Read restricts each read to one byte while preserving the underlying error.
func (r byteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.Reader.Read(p)
}

// shortWriter violates the full-write contract to exercise framing failure paths.
type shortWriter struct{ err error }

// Write reports a short write or the injected error without consuming data.
func (w shortWriter) Write(p []byte) (int, error) { return len(p) / 2, w.err }

// TestFrames verifies fragmented/coalesced decoding, exact lengths, and size limits.
func TestFrames(t *testing.T) {
	payloads := [][]byte{{0xc0, 0x21, 1, 2}, {0, 0x21, 0x45}, bytes.Repeat([]byte{7}, MaxFramePayload)}
	var wire bytes.Buffer
	for _, payload := range payloads {
		if err := WriteFrame(&wire, payload); err != nil {
			t.Fatal(err)
		}
	}
	reader := byteReader{&wire}
	for _, want := range payloads {
		got, err := ReadFrame(reader)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("round trip: len=%d err=%v", len(got), err)
		}
	}
	if _, err := ReadFrame(reader); !errors.Is(err, io.EOF) {
		t.Fatalf("end of stream: %v", err)
	}
	for _, payload := range [][]byte{nil, make([]byte, MaxFramePayload+1)} {
		if err := WriteFrame(&wire, payload); !errors.Is(err, ErrInvalidFrame) {
			t.Fatalf("invalid payload: %v", err)
		}
	}
	if err := WriteFrame(shortWriter{}, []byte{1}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write: %v", err)
	}
	injected := errors.New("write failure")
	if err := WriteFrame(shortWriter{err: injected}, []byte{1}); !errors.Is(err, injected) {
		t.Fatalf("write failure: %v", err)
	}
}

// TestFrameRejections checks malformed headers before allocation and truncated input.
func TestFrameRejections(t *testing.T) {
	cases := []struct {
		name string
		wire []byte
		err  error
	}{
		{"partial-header", []byte{0}, io.ErrUnexpectedEOF},
		{"partial-payload", []byte{0, 8, 0x50, 0x50, 0, 2, 1}, io.ErrUnexpectedEOF},
		{"missing-payload", []byte{0, 8, 0x50, 0x50, 0, 2}, io.EOF},
		{"wrong-marker", []byte{0, 7, 0, 0, 0, 1, 1}, ErrInvalidFrame},
		{"wrong-total", []byte{0, 8, 0x50, 0x50, 0, 1, 1}, ErrInvalidFrame},
		{"empty", []byte{0, 6, 0x50, 0x50, 0, 0}, ErrInvalidFrame},
		{"overflow", []byte{0, 0, 0x50, 0x50, 0xff, 0xff}, ErrInvalidFrame},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ReadFrame(bytes.NewReader(tc.wire)); !errors.Is(err, tc.err) {
				t.Fatalf("got %v, want %v", err, tc.err)
			}
		})
	}
}

// FuzzFrame checks arbitrary frames for bounded decoding and exact round trips.
func FuzzFrame(f *testing.F) {
	f.Add([]byte{0, 8, 0x50, 0x50, 0, 2, 0xc0, 0x21})
	f.Add([]byte("HTTP/1.1 403 Forbidden\r\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		payload, err := ReadFrame(bytes.NewReader(wire))
		if err != nil {
			return
		}
		if len(payload) == 0 || len(payload) > MaxFramePayload {
			t.Fatal("unbounded frame payload")
		}
		consumed := int(binary.BigEndian.Uint16(wire[:2]))
		var encoded bytes.Buffer
		if err := WriteFrame(&encoded, payload); err != nil || !bytes.Equal(encoded.Bytes(), wire[:consumed]) {
			t.Fatalf("frame round trip failed: %v", err)
		}
	})
}
