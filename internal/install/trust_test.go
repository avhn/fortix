package install

import (
	"io/fs"
	"os/user"
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

// TestTrustedSystemGroupDirectories verifies that root-owned directories writable
// only by wheel or daemon (macOS /var/run) are trusted, while other group-writable,
// world-writable, sticky or non-root entries are refused.
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
		ok   bool
	}{
		{name: "root 0755", mode: fs.ModeDir | 0o755, ok: true},
		{name: "daemon group writable", mode: fs.ModeDir | 0o775, gid: daemon, ok: true},
		{name: "wheel group writable", mode: fs.ModeDir | 0o775, ok: true},
		{name: "other group writable", mode: fs.ModeDir | 0o775, gid: 4242},
		{name: "world writable", mode: fs.ModeDir | 0o777},
		{name: "sticky", mode: fs.ModeDir | fs.ModeSticky | 0o755},
		{name: "not root", mode: fs.ModeDir | 0o755, uid: 501},
		{name: "group writable file", mode: 0o775},
	}
	i := &installer{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := i.trusted(statInfo{mode: tc.mode, stat: &syscall.Stat_t{Uid: tc.uid, Gid: tc.gid}})
			if (err == nil) != tc.ok {
				t.Fatalf("trusted = %v, want ok %v", err, tc.ok)
			}
		})
	}
}
