//go:build darwin || linux

package prompt

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/term"
)

// FuzzHiddenLine verifies bounded descriptor input and exact first-line parsing without a terminal.
// Temporary regular files make all input ready without a writer goroutine or a blocking pipe.
func FuzzHiddenLine(f *testing.F) {
	for _, input := range []string{"test-password\nnext\n", "a\r\n", "", "a"} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > maxInput+2 {
			t.Skip("input exceeds descriptor test bound")
		}
		file, err := os.CreateTemp(t.TempDir(), "input")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = file.Close() }()
		if _, err := file.WriteString(input); err != nil {
			t.Fatal(err)
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		got, err := readHiddenLine(ctx, context.Background(), int(file.Fd()))
		index := strings.IndexByte(input, '\n')
		if index < 0 || index > maxInput {
			if err == nil || len(got) != 0 {
				t.Fatal("accepted unterminated or oversized line")
			}
			return
		}
		if err != nil || string(got) != strings.TrimSuffix(input[:index], "\r") {
			t.Fatalf("first line: %q %v", got, err)
		}
		position, err := file.Seek(0, io.SeekCurrent)
		if err != nil || position != int64(index+1) {
			t.Fatalf("read beyond first line: %d %v", position, err)
		}
	})
}

// TestHiddenPassword exercises real terminal setup and restoration on successful reads,
// SIGINT, SIGTERM, and context cancellation using private pseudo terminals only.
func TestHiddenPassword(t *testing.T) {
	for _, action := range []string{"password", "interrupt", "terminate", "context"} {
		t.Run(action, func(t *testing.T) {
			master, slave := testPTY(t)
			fd := int(slave.Fd())
			before, err := term.GetState(fd)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			// result carries a synthetic password or a read failure back to the test.
			type result struct {
				password string
				err      error
			}
			done := make(chan result, 1)
			go func() {
				password, err := (Terminal{Input: slave, Output: io.Discard}).Password(ctx, "Password: ", true)
				done <- result{password, err}
			}()
			// Wait for echo suppression before writing input or delivering a signal.
			for terminalEcho(t, fd) {
				if ctx.Err() != nil {
					t.Fatal("terminal did not enter hidden input mode")
				}
				time.Sleep(time.Millisecond)
			}
			var want error
			switch action {
			case "password":
				if _, err := master.Write([]byte("test-password\n")); err != nil {
					t.Fatal(err)
				}
			case "interrupt", "terminate":
				sig := syscall.SIGINT
				if action == "terminate" {
					sig = syscall.SIGTERM
				}
				if err := syscall.Kill(os.Getpid(), sig); err != nil {
					t.Fatal(err)
				}
				want = ErrCancelled
			case "context":
				cancel()
				want = context.Canceled
			}
			select {
			case got := <-done:
				if !errors.Is(got.err, want) || (want == nil && got.password != "test-password") || (want != nil && got.password != "") {
					t.Fatalf("response: %q %v", got.password, got.err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("hidden read did not finish")
			}
			after, err := term.GetState(fd)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("terminal state not restored: %v", err)
			}
		})
	}
}
