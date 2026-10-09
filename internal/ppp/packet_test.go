package ppp

import (
	"bytes"
	"errors"
	"testing"
)

// TestControlDecoding covers declared-length padding and both length boundaries.
func TestControlDecoding(t *testing.T) {
	packet := controlPacket(ProtocolLCP, ConfigureRequest, 7, []byte{1, 4, 5, 74})[2:]
	decoded, err := DecodeControl(append(bytes.Clone(packet), 0, 0))
	if err != nil || decoded.Code != ConfigureRequest || decoded.ID != 7 || !bytes.Equal(decoded.Data, packet[4:]) {
		t.Fatalf("decode: %+v, %v", decoded, err)
	}
	for _, data := range [][]byte{nil, {1, 1, 0}, {1, 1, 0, 0}, {1, 1, 0, 3}, {1, 1, 0, 5}, make([]byte, DefaultMRU+1)} {
		if _, err := DecodeControl(data); !errors.Is(err, ErrMalformed) {
			t.Fatalf("accepted invalid control field: %x", data)
		}
	}
}

// TestOptionDecoding preserves option order while rejecting malformed/duplicate
// encodings that otherwise allow conflicting changes to one negotiated value.
func TestOptionDecoding(t *testing.T) {
	body := append([]byte{1, 4, 5, 74}, uint32Option(5, 123)...)
	options, err := DecodeOptions(body)
	if err != nil || len(options) != 2 || options[0].Type != 1 || options[1].Type != 5 {
		t.Fatalf("options: %+v, %v", options, err)
	}
	for _, data := range [][]byte{{1}, {1, 0}, {1, 1}, {1, 3}, {1, 2, 1, 2}, make([]byte, DefaultMRU)} {
		if _, err := DecodeOptions(data); !errors.Is(err, ErrMalformed) {
			t.Fatalf("accepted invalid option field: %x", data)
		}
	}
	if options, err := DecodeOptions(nil); err != nil || len(options) != 0 {
		t.Fatalf("empty request: %+v, %v", options, err)
	}
}

// FuzzDecodeControl asserts successful decoding round-trips the declared body
// without retaining padding, and that the decoder never panics on untrusted bytes.
func FuzzDecodeControl(f *testing.F) {
	f.Add([]byte{1, 42, 0, 8, 1, 4, 5, 74})
	f.Add([]byte{9, 12, 0, 8, 1, 2, 3, 4, 0})
	f.Add([]byte{1, 1, 0, 3})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		control, err := DecodeControl(data)
		if err != nil {
			return
		}
		wire := controlPacket(ProtocolLCP, control.Code, control.ID, control.Data)[2:]
		if !bytes.Equal(wire, data[:len(wire)]) {
			t.Fatalf("control round-trip mismatch: %x, %x", wire, data)
		}
	})
}

// FuzzDecodeOptions asserts successful decoding preserves every option byte and
// order; length errors and duplicates remain safe rejection paths.
func FuzzDecodeOptions(f *testing.F) {
	f.Add([]byte{1, 4, 5, 74, 5, 6, 1, 2, 3, 4})
	f.Add([]byte{3, 6, 0, 0, 0, 0, 129, 6, 0, 0, 0, 0})
	f.Add([]byte{1, 2, 1, 2})
	f.Add([]byte{1})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		options, err := DecodeOptions(data)
		if err != nil {
			return
		}
		wire := make([]byte, 0, len(data))
		for _, option := range options {
			wire = append(wire, optionBytes(option)...)
		}
		if !bytes.Equal(wire, data) {
			t.Fatalf("option round-trip mismatch: %x, %x", wire, data)
		}
	})
}
