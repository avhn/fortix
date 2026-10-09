//go:build windows

package prompt

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

// keySequence injects one key-down per UTF-16 unit and reports EOF at exhaustion.
func keySequence(units []uint16) func() (consoleKey, error) {
	i := 0
	return func() (consoleKey, error) {
		if i == len(units) {
			return consoleKey{}, io.EOF
		}
		char := units[i]
		i++
		return consoleKey{char: char, repeat: 1, down: true}, nil
	}
}

// TestWindowsLineEditing checks exact text, scalar backspace, cancellation and invalid UTF-16.
func TestWindowsLineEditing(t *testing.T) {
	for _, tc := range []struct {
		name  string
		units []uint16
		want  string
		err   error
	}{
		{"cr", []uint16{'a', 'b', '\r', 'x'}, "ab", nil},
		{"lf", []uint16{'a', '\n'}, "a", nil},
		{"empty", []uint16{'\r'}, "", nil},
		{"backspace", []uint16{'\b', 'a', 'b', '\b', 'c', '\r'}, "ac", nil},
		{"surrogate", []uint16{0xd834, 0xdd1e, '\r'}, "\U0001d11e", nil},
		{"scalar erase", []uint16{'a', 0xd834, 0xdd1e, '\b', '\r'}, "a", nil},
		{"pending erase", []uint16{0xd834, '\b', 'a', '\r'}, "a", nil},
		{"interrupt", []uint16{'a', 3}, "", ErrCancelled},
		{"empty eof", nil, "", io.EOF},
		{"partial eof", []uint16{'a'}, "", io.EOF},
		{"unpaired low", []uint16{0xdd1e, '\r'}, "", ErrFailed},
		{"unpaired high", []uint16{0xd834, '\r'}, "", ErrFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := editConsoleLine(context.Background(), context.Background(), keySequence(tc.units))
			if !errors.Is(err, tc.err) || string(got) != tc.want {
				t.Fatalf("line = %q %v, want %q %v", got, err, tc.want, tc.err)
			}
		})
	}
}

// TestWindowsInputBounds checks both byte-sized and multibyte response limits.
func TestWindowsInputBounds(t *testing.T) {
	for _, char := range []uint16{'a', 0x20ac} {
		for _, extra := range []int{0, 1} {
			count := maxInput + extra
			if char != 'a' {
				count = maxInput/3 + extra
			}
			units := make([]uint16, count+1)
			for i := 0; i < count; i++ {
				units[i] = char
			}
			units[count] = '\r'
			got, err := editConsoleLine(context.Background(), context.Background(), keySequence(units))
			if extra == 0 {
				if err != nil || len(got) > maxInput {
					t.Fatalf("rejected bounded input: %v", err)
				}
			} else if !errors.Is(err, ErrFailed) || len(got) != 0 {
				t.Fatal("accepted oversized response")
			}
		}
	}
}

// TestWindowsKeyEvents verifies repeat counts, ignored key-up and post-read cancellation.
func TestWindowsKeyEvents(t *testing.T) {
	keys := []consoleKey{{char: 'x', repeat: 1}, {char: 'a', repeat: 3, down: true}, {char: '\r', repeat: 1, down: true}}
	i := 0
	got, err := editConsoleLine(context.Background(), context.Background(), func() (consoleKey, error) {
		key := keys[i]
		i++
		return key, nil
	})
	if err != nil || string(got) != "aaa" {
		t.Fatalf("key events: %q %v", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	got, err = editConsoleLine(ctx, context.Background(), func() (consoleKey, error) {
		cancel()
		return consoleKey{char: '\r', repeat: 1, down: true}, nil
	})
	if !errors.Is(err, context.Canceled) || len(got) != 0 {
		t.Fatal("returned a response after cancellation")
	}
	interrupted, stop := context.WithCancel(context.Background())
	stop()
	if _, err := editConsoleLine(context.Background(), interrupted, keySequence(nil)); !errors.Is(err, ErrCancelled) {
		t.Fatal("lost interrupt")
	}
}

// TestWindowsNonConsoleFallback retains the shared reader's EOF and first-line semantics.
// The duplicate handle must not close or read beyond the caller's input file.
func TestWindowsNonConsoleFallback(t *testing.T) {
	for _, input := range []string{"first\r\nsecond\n", "partial", "", strings.Repeat("a", maxInput+1)} {
		file, err := os.CreateTemp(t.TempDir(), "input")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.WriteString(input); err != nil {
			t.Fatal(err)
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		got, err := hiddenPassword(context.Background(), int(file.Fd()))
		want, wantErr := readLine(strings.NewReader(input))
		if (err != nil) != (wantErr != nil) || string(got) != want {
			t.Fatalf("fallback: %q %v", got, err)
		}
		if _, err := file.Stat(); err != nil {
			t.Fatal("closed caller input")
		}
		if input == "first\r\nsecond\n" {
			rest, err := io.ReadAll(file)
			if err != nil || string(rest) != "second\n" {
				t.Fatal("consumed subsequent response")
			}
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
