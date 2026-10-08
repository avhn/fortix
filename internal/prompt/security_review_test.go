package prompt

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

// TestKDialogEscapesMarkup passes remote text as escaped HTML in both credential
// and trust dialogs; literal tags cannot replace their visible security explanation.
func TestKDialogEscapesMarkup(t *testing.T) {
	for _, password := range []bool{false, true} {
		r := &fakeRunner{output: []byte("fixture-password\n")}
		n := Native{Runner: r, platform: "linux", LookPath: func(name string) (string, error) {
			if name == "kdialog" {
				return "/usr/bin/kdialog", nil
			}
			return "", exec.ErrNotFound
		}}
		if _, _, err := n.dialog(context.Background(), "<b>title</b>", "<img src=x> & issuer", password); err != nil {
			t.Fatal(err)
		}
		args := strings.Join(r.args, " ")
		if strings.Contains(args, "<img") || strings.Contains(args, "<b>") || !strings.Contains(args, "&lt;img src=x&gt; &amp; issuer") || !strings.Contains(args, "&lt;b&gt;title&lt;/b&gt;") {
			t.Fatal("kdialog received active markup")
		}
	}
}
