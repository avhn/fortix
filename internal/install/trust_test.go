//go:build darwin || linux

package install

import (
	"io/fs"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// statInfo is a synthetic FileInfo carrying a chosen owner, group and mode so the
// trust policy can be exercised without root-owned fixtures.
type statInfo struct {
	mode fs.FileMode
	stat *syscall.Stat_t
}

func (s statInfo) Name() string       { return "entry" }
func (s statInfo) Size() int64        { return 0 }
func (s statInfo) Mode() fs.FileMode  { return s.mode }
func (s statInfo) ModTime() time.Time { return time.Time{} }
func (s statInfo) IsDir() bool        { return s.mode.IsDir() }
func (s statInfo) Sys() any           { return s.stat }

// TestTrustedSystemGroupDirectories verifies that the runtime directory holding
// the sockets may be group-writable by wheel or daemon (macOS /var/run), while
// the same mode elsewhere and other group-writable, world-writable, sticky or
// non-root entries are refused.
func TestTrustedSystemGroupDirectories(t *testing.T) {
	daemon := uint32(1)
	if group, err := user.LookupGroup("daemon"); err == nil {
		if gid, err := strconv.ParseUint(group.Gid, 10, 32); err == nil {
			daemon = uint32(gid)
		}
	} else {
		t.Skip("daemon group unavailable")
	}
	cases := []struct {
		name string
		mode fs.FileMode
		uid  uint32
		gid  uint32
		path string
		ok   bool
	}{
		{name: "root 0755", mode: fs.ModeDir | 0o755, ok: true},
		{name: "daemon runtime base", mode: fs.ModeDir | 0o775, gid: daemon, path: "runtime", ok: true},
		{name: "wheel runtime base", mode: fs.ModeDir | 0o775, path: "runtime", ok: true},
		{name: "daemon elsewhere", mode: fs.ModeDir | 0o775, gid: daemon, path: "/usr/local"},
		{name: "other group runtime base", mode: fs.ModeDir | 0o775, gid: 4242, path: "runtime"},
		{name: "world writable", mode: fs.ModeDir | 0o777},
		{name: "sticky", mode: fs.ModeDir | fs.ModeSticky | 0o755},
		{name: "not root", mode: fs.ModeDir | 0o755, uid: 501},
		{name: "group writable file", mode: 0o775},
	}
	base := t.TempDir()
	runtime, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	i := &installer{}
	i.paths.ControlSocket = filepath.Join(base, "fortix", "fortix.sock")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.path
			if path == "runtime" {
				path = runtime
			}
			err := i.trustedAt(statInfo{mode: tc.mode, stat: &syscall.Stat_t{Uid: tc.uid, Gid: tc.gid}}, path)
			if (err == nil) != tc.ok {
				t.Fatalf("trusted = %v, want ok %v", err, tc.ok)
			}
		})
	}
}
