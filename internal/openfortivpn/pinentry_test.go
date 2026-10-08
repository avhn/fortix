package openfortivpn

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fragmentedReader limits each read to n bytes to simulate fragmented pipe delivery.
// It delegates EOF and other read errors unchanged to its wrapped reader.
type fragmentedReader struct {
	r io.Reader
	n int
}

// Read copies at most n bytes into p and returns the wrapped reader's result.
func (r fragmentedReader) Read(p []byte) (int, error) {
	if len(p) > r.n {
		p = p[:r.n]
	}
	return r.r.Read(p)
}

// TestServeFraming checks coalesced and byte-fragmented commands and suffix routing.
// Escaped metadata must decode exactly and BYE must prevent later callbacks.
func TestServeFraming(t *testing.T) {
	for _, chunk := range []int{1, 2, 17, 4096} {
		for _, suffix := range []string{"_password", "_otp", "_2fa"} {
			input := "SETTITLE VPN\nSETDESC Enter%20credential\nOPTION ttyname=example\nSETKEYINFO work" + suffix + "\nSETPROMPT Enter%25%0D%0A+\nUNKNOWN ignored\nGETPIN\nBYE\nGETPIN\n"
			var output bytes.Buffer
			var requests []Request
			err := Serve(context.Background(), fragmentedReader{r: strings.NewReader(input), n: chunk}, &output, func(_ context.Context, request Request) (string, error) {
				requests = append(requests, request)
				return "example%\r\n+", nil
			})
			kind := Code
			if suffix == "_password" {
				kind = Password
			}
			wantRequests := []Request{{Kind: kind, KeyInfo: "work" + suffix, Prompt: "Enter%\r\n+"}}
			want := "OK fortix pinentry\n" + strings.Repeat("OK\n", 6) + "D example%25%0D%0A+\nOK\nOK\n"
			if err != nil || !reflect.DeepEqual(requests, wantRequests) || output.String() != want {
				t.Fatalf("chunk %d suffix %s: %v, %#v, %q", chunk, suffix, err, requests, output.String())
			}
		}
	}
}

// TestIgnoredSetters checks that unused metadata and options are acknowledged without
// percent decoding, even when malformed escapes would fail for keyinfo or prompt input.
func TestIgnoredSetters(t *testing.T) {
	for _, command := range []string{"OPTION", "SETTITLE", "SETDESC", "UNKNOWN"} {
		for _, argument := range []string{"%", "%GG", "%0", "literal%text"} {
			var output bytes.Buffer
			err := Serve(context.Background(), strings.NewReader(command+" "+argument+"\nBYE\n"), &output, func(_ context.Context, _ Request) (string, error) {
				t.Fatal("ignored setter requested a credential")
				return "", nil
			})
			if err != nil || output.String() != "OK fortix pinentry\nOK\nOK\n" {
				t.Fatalf("%s %q: %v, %q", command, argument, err, output.String())
			}
		}
	}
}

// TestLongPinentryMetadata checks escaped keyinfo and prompt lines above the outgoing
// data bound, exact input bounds, and rejection beyond them with no callback or secret.
func TestLongPinentryMetadata(t *testing.T) {
	for _, command := range []string{"SETKEYINFO", "SETPROMPT"} {
		for _, size := range []int{MaxAssuanLine + 1, maxAssuanCommand - 1, maxAssuanCommand} {
			argument := strings.Repeat("%2E", (size-len(command)-1-len("_password"))/3)
			argument += strings.Repeat("x", size-len(command)-1-len("_password")-len(argument)) + "_password"
			line := command + " " + argument + "\n"
			var output bytes.Buffer
			var got Request
			called := false
			err := Serve(context.Background(), fragmentedReader{r: strings.NewReader("SETKEYINFO work_password\n" + line + "GETPIN\n"), n: 7}, &output, func(_ context.Context, request Request) (string, error) {
				called, got = true, request
				return "example", nil
			})
			if size == maxAssuanCommand {
				if err == nil || called || !strings.Contains(output.String(), cancelReply) {
					t.Fatal("oversized metadata accepted")
				}
				continue
			}
			want, decodeErr := percentDecode(argument)
			if decodeErr != nil || err != nil || !called || (command == "SETKEYINFO" && got.KeyInfo != want) || (command == "SETPROMPT" && got.Prompt != want) {
				t.Fatalf("metadata command %s size %d: %v, %v", command, size, err, decodeErr)
			}
		}
	}
}

// closingDataWriter models a peer that accepts one data write, then closes its pipe.
// It stores that first reply only so tests can verify the acknowledgement was coalesced.
type closingDataWriter struct {
	closed bool
	data   string
}

// Write records the first data reply and refuses later writes with io.ErrClosedPipe.
// Earlier non-data replies succeed without retaining their metadata.
func (w *closingDataWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	if bytes.HasPrefix(p, []byte("D ")) {
		w.closed, w.data = true, string(p)
	}
	return len(p), nil
}

// TestPINReplySingleWrite proves the data and OK records reach a one-read peer together.
// EOF after GETPIN must return success instead of a spurious write error after delivery.
func TestPINReplySingleWrite(t *testing.T) {
	w := &closingDataWriter{}
	err := Serve(context.Background(), strings.NewReader("SETKEYINFO work_password\nGETPIN\n"), w, func(_ context.Context, _ Request) (string, error) {
		return "example%\r\n", nil
	})
	if err != nil || w.data != "D example%25%0D%0A\nOK\n" {
		t.Fatalf("reply was not coalesced: %v, %q", err, w.data)
	}
}

// TestServeCancellation covers callback refusal, unknown key hints, and context
// cancellation. No callback error text or returned secret may enter protocol replies.
func TestServeCancellation(t *testing.T) {
	for _, hint := range []string{"work_password", "work_unknown", ""} {
		var output bytes.Buffer
		called := false
		err := Serve(context.Background(), strings.NewReader("SETKEYINFO "+hint+"\nGETPIN\nBYE\n"), &output, func(_ context.Context, _ Request) (string, error) {
			called = true
			return "do-not-print", errors.New("do-not-print")
		})
		if err != nil || called != (hint == "work_password") || strings.Contains(output.String(), "do-not-print") || !strings.Contains(output.String(), cancelReply) {
			t.Fatalf("incorrect cancellation: %v, %q", err, output.String())
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	var output bytes.Buffer
	err := Serve(ctx, strings.NewReader("SETKEYINFO work_password\nGETPIN\n"), &output, func(_ context.Context, _ Request) (string, error) {
		cancel()
		return "do-not-print", nil
	})
	if !errors.Is(err, context.Canceled) || !strings.Contains(output.String(), cancelReply) || strings.Contains(output.String(), "do-not-print") {
		t.Fatalf("context not respected: %v, %q", err, output.String())
	}
}

// TestServeBlockedCancellation proves cancellation closes an owned pipe reader and
// returns promptly while idle. A bounded wait prevents a broken implementation hanging.
func TestServeBlockedCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, w := io.Pipe()
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
		if err := w.Close(); err != nil {
			t.Error(err)
		}
	}()
	var output bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, r, &output, func(_ context.Context, _ Request) (string, error) {
			return "", nil
		})
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || !strings.Contains(output.String(), cancelReply) {
			t.Fatalf("incorrect cancellation: %v, %q", err, output.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled reader remained blocked")
	}
}

// brokenReader injects a read failure to test error propagation without external I/O.
type brokenReader struct{}

// Read returns no data and io.ErrUnexpectedEOF for every destination.
func (brokenReader) Read(_ []byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// brokenWriter injects failed or short writes at a chosen reply number.
type brokenWriter struct {
	writes int
	failAt int
	short  bool
}

// Write succeeds before failAt, then returns a short write or io.ErrClosedPipe.
// It never stores the data supplied by the protocol responder.
func (w *brokenWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.writes == w.failAt {
		if w.short {
			return len(p) - 1, nil
		}
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}

// TestServeFailures checks EOF, malformed escapes, command/response bounds, nil
// dependencies, and read/write failures. Failure replies must not disclose secrets.
func TestServeFailures(t *testing.T) {
	ask := func(_ context.Context, _ Request) (string, error) { return "example", nil }
	for _, input := range []string{"", "OPTION test\n", "BYE\n"} {
		if err := Serve(context.Background(), strings.NewReader(input), io.Discard, ask); err != nil {
			t.Fatal(err)
		}
	}
	for _, input := range []string{"SETPROMPT %\n", "SETPROMPT %GG\n", "SETPROMPT %0\n", "SETKEYINFO bad\x00\n", strings.Repeat("x", maxAssuanCommand) + "\n", strings.Repeat("x", maxAssuanCommand+20) + "\n"} {
		var output bytes.Buffer
		if err := Serve(context.Background(), strings.NewReader(input), &output, ask); err == nil || !strings.Contains(output.String(), cancelReply) {
			t.Fatalf("malformed input accepted: %v, %q", err, output.String())
		}
	}
	if err := Serve(context.Background(), strings.NewReader(strings.Repeat("x", maxAssuanCommand-1)+"\n"), io.Discard, ask); err != nil {
		t.Fatalf("exact-limit command rejected: %v", err)
	}
	for _, secret := range []string{strings.Repeat("x", MaxAssuanLine), strings.Repeat("%", MaxAssuanLine/2)} {
		var output bytes.Buffer
		err := Serve(context.Background(), strings.NewReader("SETKEYINFO work_password\nGETPIN\n"), &output, func(_ context.Context, _ Request) (string, error) { return secret, nil })
		if err == nil || strings.Contains(output.String(), "D ") || !strings.Contains(output.String(), cancelReply) {
			t.Fatalf("oversized response written: %v, %q", err, output.String())
		}
	}
	if err := Serve(context.Background(), brokenReader{}, io.Discard, ask); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("lost reader error: %v", err)
	}
	for _, input := range []string{"OPTION test\nGETPIN\n", "SETKEYINFO work_password\nGETPIN\nBYE\n", "UNKNOWN\nBYE\n"} {
		for failAt := 1; failAt <= 4; failAt++ {
			for _, short := range []bool{false, true} {
				w := &brokenWriter{failAt: failAt, short: short}
				err := Serve(context.Background(), strings.NewReader(input), w, ask)
				if w.writes >= failAt && err == nil {
					t.Fatal("writer failure ignored")
				}
			}
		}
	}
	for _, err := range []error{
		Serve(nil, strings.NewReader(""), io.Discard, ask), //nolint:staticcheck // Intentionally verify the nil-context boundary rejects invalid callers.
		Serve(context.Background(), nil, io.Discard, ask),
		Serve(context.Background(), strings.NewReader(""), nil, ask),
		Serve(context.Background(), strings.NewReader(""), io.Discard, nil),
	} {
		if err == nil {
			t.Fatal("nil dependency accepted")
		}
	}
}

// FuzzPercentEncoding verifies byte-exact Assuan escape round trips and exercises
// malformed percent decoding. Plus signs must remain literal rather than become spaces.
func FuzzPercentEncoding(f *testing.F) {
	for _, input := range []string{"", "example%\r\n", "%00%25%0d%0A", "%", "%GG", "é+", "\x00"} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		decoded, err := percentDecode(percentEscape(input))
		if err != nil || decoded != input {
			t.Fatalf("round trip failed: %v", err)
		}
		_, _ = percentDecode(input)
	})
}

// FuzzServe checks arbitrary fragmented Assuan streams for panic safety, bounded
// replies, and safe escaping of callback responses, using no pipes or network access.
func FuzzServe(f *testing.F) {
	for _, input := range []string{"BYE\n", "SETKEYINFO work_password\nGETPIN\nBYE\n", "SETPROMPT %25%0D%0A\n", "GETPIN\n", "SETPROMPT %\n", "OPTION %GG\n", "SETKEYINFO " + strings.Repeat("%2E", 600) + "_password\nGETPIN\n"} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		var output bytes.Buffer
		_ = Serve(context.Background(), fragmentedReader{r: strings.NewReader(input), n: 7}, &output, func(_ context.Context, _ Request) (string, error) { return "example%\r\n", nil })
		for line := range strings.SplitSeq(strings.TrimSuffix(output.String(), "\n"), "\n") {
			if len(line)+1 > MaxAssuanLine || strings.ContainsRune(line, '\r') {
				t.Fatal("invalid reply framing")
			}
		}
	})
}
