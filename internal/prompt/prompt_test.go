package prompt

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// fakeRunner captures only synthetic arguments and returns scripted stdout without launching UI.
type fakeRunner struct {
	program string
	args    []string
	script  string
	output  []byte
	err     error
	calls   int
}

// Run records the request, verifies a deadline exists, and returns synthetic results.
func (r *fakeRunner) Run(ctx context.Context, program string, args []string, stdin io.Reader) ([]byte, error) {
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("missing deadline")
	}
	r.program, r.args = program, append([]string(nil), args...)
	data, err := io.ReadAll(stdin)
	if err != nil {
		return nil, err
	}
	r.script = string(data)
	r.calls++
	return r.output, r.err
}

// TestAppleDialogs verifies literal text arguments, hidden input, cancellation, and sanitized failures.
func TestAppleDialogs(t *testing.T) {
	title, message := `" & do shell script "false"`, "Line one\nLine two"
	r := &fakeRunner{output: []byte("ok: test-password \n")}
	n := Native{Runner: r, platform: "darwin"}
	got, err := n.Password(context.Background(), title, message)
	if err != nil || got != " test-password " {
		t.Fatalf("password %q %v", got, err)
	}
	if r.program != "/usr/bin/osascript" || !reflect.DeepEqual(r.args, []string{"-", title, message}) {
		t.Fatalf("command: %s %q", r.program, r.args)
	}
	if !strings.Contains(r.script, "hidden answer") || strings.Contains(r.script, title) || strings.Contains(strings.Join(r.args, " "), "test-password") {
		t.Fatal("unsafe dialog command")
	}
	for _, tc := range []struct {
		out  string
		want string
		err  error
	}{
		{"ok:cancel:\n", "cancel:", nil}, {"cancel:\n", "", ErrCancelled}, {"invalid\n", "", ErrFailed},
	} {
		r.output = []byte(tc.out)
		got, err := n.Password(context.Background(), "title", "message")
		if got != tc.want || !errors.Is(err, tc.err) {
			t.Fatalf("output %q: %q %v", tc.out, got, err)
		}
	}
	for _, tc := range []struct {
		out  string
		want bool
		err  error
	}{
		{"Yes\n", true, nil}, {"No\n", false, nil}, {"cancel:\n", false, ErrCancelled}, {"unexpected", false, ErrFailed},
	} {
		r.output = []byte(tc.out)
		got, err := n.Confirm(context.Background(), title, message)
		if got != tc.want || !errors.Is(err, tc.err) {
			t.Fatalf("confirm %q: %v %v", tc.out, got, err)
		}
	}
	r.err = errors.New("test-password leaked by command")
	if got, err := n.Password(context.Background(), title, message); got != "" || !errors.Is(err, ErrFailed) {
		t.Fatal("unsafe command error")
	}
}

// TestLinuxTools verifies discovery priority, literal arguments, unavailable UI, and notifications.
func TestLinuxTools(t *testing.T) {
	for _, tool := range []string{"zenity", "kdialog", "none"} {
		t.Run(tool, func(t *testing.T) {
			r := &fakeRunner{output: []byte("test-password\n")}
			n := Native{Runner: r, platform: "linux", LookPath: func(name string) (string, error) {
				if name == tool {
					return "/usr/bin/" + name, nil
				}
				return "", exec.ErrNotFound
			}}
			got, err := n.Password(context.Background(), "title", "literal message")
			if tool == "none" {
				if !errors.Is(err, ErrUnavailable) || r.calls != 0 {
					t.Fatal(err)
				}
				return
			}
			if err != nil || got != "test-password" || r.program != "/usr/bin/"+tool {
				t.Fatalf("password: %q %v", got, err)
			}
			if tool == "zenity" && !reflect.DeepEqual(r.args, []string{"--password", "--title=title"}) {
				t.Fatalf("password arguments: %q", r.args)
			}
			if strings.Contains(strings.Join(r.args, " "), "test-password") || r.script != "" {
				t.Fatal("secret in command")
			}
			if got, err := n.Confirm(context.Background(), "title", "<span>literal & message</span>"); !got || err != nil {
				t.Fatalf("confirm %v %v", got, err)
			}
			if tool == "zenity" && !reflect.DeepEqual(r.args, []string{"--question", "--title=title", "--no-markup", "--text=<span>literal & message</span>"}) {
				t.Fatalf("confirmation markup enabled: %q", r.args)
			}
		})
	}
	r := &fakeRunner{}
	n := Native{Runner: r, platform: "linux", LookPath: func(name string) (string, error) { return "/usr/bin/" + name, nil }}
	if err := n.Notify(context.Background(), "--title", "body"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.args, []string{"--", "--title", "body"}) {
		t.Fatal(r.args)
	}
	n.LookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	if err := n.Notify(context.Background(), "title", "body"); err != nil || r.calls != 1 {
		t.Fatal(err)
	}
	n.platform = "darwin"
	if err := n.Notify(context.Background(), "title", "body"); err != nil {
		t.Fatal(err)
	}
	if r.script != notifyScript {
		t.Fatal("wrong notification script")
	}
	r.err = errors.New("test-password")
	if err := n.Notify(context.Background(), "title", "body"); !errors.Is(err, ErrFailed) {
		t.Fatal(err)
	}
	n.platform = "unsupported"
	if _, err := n.Password(context.Background(), "title", "message"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if err := n.Notify(context.Background(), "title", "body"); err != nil {
		t.Fatal(err)
	}
}

// TestTerminal checks explicit stdin opt-in, exact line consumption, hidden input, and confirmation.
func TestTerminal(t *testing.T) {
	reader := strings.NewReader(" test-password \r\nnext\n")
	term := Terminal{Reader: reader, Output: io.Discard, isTerminal: func(int) bool { return false }}
	if _, err := term.Password(context.Background(), "Password: ", false); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if reader.Len() != len(" test-password \r\nnext\n") {
		t.Fatal("consumed unapproved stdin")
	}
	if got, err := term.Password(context.Background(), "Password: ", true); err != nil || got != " test-password " {
		t.Fatalf("stdin: %q %v", got, err)
	}
	if got, err := readLine(reader); err != nil || got != "next" {
		t.Fatalf("read ahead: %q %v", got, err)
	}
	term.isTerminal = func(int) bool { return true }
	term.readPassword = func(int) ([]byte, error) { return []byte("hidden"), nil }
	if got, err := term.Password(context.Background(), "Password: ", false); err != nil || got != "hidden" {
		t.Fatalf("hidden: %q %v", got, err)
	}
	if got, err := term.Password(context.Background(), "Password: ", true); err != nil || got != "hidden" {
		t.Fatalf("TTY stdin opt-in: %q %v", got, err)
	}
	term.readPassword = func(int) ([]byte, error) { return []byte("hidden"), errors.New("test-password") }
	if got, err := term.Password(context.Background(), "Password: ", false); got != "" || !errors.Is(err, ErrFailed) {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		input   string
		want    bool
		invalid bool
	}{
		{"y\n", true, false}, {" YES \n", true, false}, {"n\n", false, false}, {"No\n", false, false}, {"\n", false, false}, {"maybe\n", false, true}, {"", false, true},
	} {
		term.Reader = strings.NewReader(tc.input)
		got, err := term.Confirm(context.Background(), "Continue?")
		if got != tc.want || (err != nil) != tc.invalid {
			t.Fatalf("confirm %q: %v %v", tc.input, got, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := term.Password(ctx, "Password: ", true); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := term.Confirm(ctx, "Continue?"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// TestLineLimits checks oversized responses, empty input, EOF without newline, and CRLF handling.
func TestLineLimits(t *testing.T) {
	for _, tc := range []struct {
		input, want string
		invalid     bool
	}{
		{"abc", "abc", false}, {"a\r\n", "a", false}, {"", "", true}, {strings.Repeat("a", maxInput+1), "", true},
	} {
		got, err := readLine(strings.NewReader(tc.input))
		if got != tc.want || (err != nil) != tc.invalid {
			t.Fatalf("line: len=%d got len=%d err=%v", len(tc.input), len(got), err)
		}
	}
}

// FuzzReadLine verifies bounded input parsing never panics or reads beyond the first newline.
func FuzzReadLine(f *testing.F) {
	for _, input := range []string{"test-password\nnext\n", "\r\n", "", "a"} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		r := strings.NewReader(input)
		got, err := readLine(r)
		if err == nil && len(got) > maxInput {
			t.Fatal("oversized response")
		}
		if index := strings.IndexByte(input, '\n'); index >= 0 && index <= maxInput && r.Len() != len(input)-index-1 {
			t.Fatal("read beyond line")
		}
	})
}

// FuzzConfirmation ensures malformed input never produces approval without a valid yes word.
func FuzzConfirmation(f *testing.F) {
	for _, input := range []string{"yes", "n", "", "maybe"} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		yes, err := parseConfirmation(input)
		if yes && (err != nil || (strings.ToLower(strings.TrimSpace(input)) != "y" && strings.ToLower(strings.TrimSpace(input)) != "yes")) {
			t.Fatal("invalid approval")
		}
	})
}
