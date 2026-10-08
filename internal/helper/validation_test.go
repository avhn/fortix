package helper

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/avhn/fortix/internal/paths"
)

// TestInvalidOptions rejects unsafe path layouts and unbounded control settings before
// opening any filesystem entry or socket. No supplied production path is accessed.
func TestInvalidOptions(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*Options)
	}{
		{"negative connection limit", func(o *Options) { o.MaxConnections = -1 }},
		{"excess connection limit", func(o *Options) { o.MaxConnections = 257 }},
		{"negative idle timeout", func(o *Options) { o.IdleTimeout = -time.Second }},
		{"negative record timeout", func(o *Options) { o.RecordTimeout = -time.Second }},
		{"relative path", func(o *Options) { o.Paths.Profiles = "relative" }},
		{"unclean path", func(o *Options) { o.Paths.State = "/tmp/../state" }},
		{"shared socket", func(o *Options) { o.Paths.PinentrySocket = o.Paths.ControlSocket }},
		{"shared socket directory", func(o *Options) { o.Paths.PinentrySocket = "/tmp/pinentry.sock" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := Options{Paths: paths.Paths{ControlSocket: "/tmp/control.sock", PinentrySocket: "/tmp/private/pinentry.sock", Profiles: "/tmp/profiles", State: "/tmp/state", Logs: "/tmp/logs", Pinentry: "/tmp/fortix-pinentry"}}
			tc.alter(&o)
			if _, err := New(o); err == nil {
				t.Fatal("unsafe options accepted")
			}
		})
	}
}

// TestInvalidRecoveryRecords refuses malformed or unsafe journal entries before
// invoking process or network recovery. Files, links, and FIFOs are all temporary.
func TestInvalidRecoveryRecords(t *testing.T) {
	for _, tc := range []struct {
		name, filename, data string
		mode                 os.FileMode
		kind                 string
	}{
		{"invalid filename", "Work.json", `{}`, 0600, "file"},
		{"malformed json", "work.json", `{"profile":"work"`, 0600, "file"},
		{"duplicate identity", "work.json", `{"profile":"work","pid":123,"pid":124}`, 0600, "file"},
		{"mismatched profile", "work.json", `{"profile":"other","attempt":1,"pid":1073741824,"start_time":"missing"}`, 0600, "file"},
		{"zero generation", "work.json", `{"profile":"work","attempt":0,"pid":1073741824,"start_time":"missing"}`, 0600, "file"},
		{"invalid pid", "work.json", `{"profile":"work","attempt":1,"pid":1,"start_time":"missing"}`, 0600, "file"},
		{"missing birth time", "work.json", `{"profile":"work","attempt":1,"pid":1073741824,"start_time":""}`, 0600, "file"},
		{"public record", "work.json", `{}`, 0644, "file"},
		{"symlink", "work.json", `{}`, 0600, "symlink"},
		{"fifo", "work.json", `{}`, 0600, "fifo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tc.filename)
			var err error
			switch tc.kind {
			case "symlink":
				err = os.Symlink(filepath.Join(t.TempDir(), "missing"), path)
			case "fifo":
				err = unix.Mkfifo(path, 0600)
			default:
				err = os.WriteFile(path, []byte(tc.data), tc.mode)
			}
			if err != nil {
				t.Fatal(err)
			}
			n := &recoveryNetwork{}
			s := &Server{opts: Options{Paths: paths.Paths{State: dir}, Network: n}}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if s.recover(ctx) == nil {
				t.Fatal("unsafe journal accepted")
			}
			if !reflect.DeepEqual(n.recovered, Journal{}) {
				t.Fatal("unsafe journal reached network recovery")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatal("rejected journal was removed")
			}
		})
	}
}
