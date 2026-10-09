package winfs

import (
	"errors"

	"golang.org/x/sys/windows"
)

// SameVolume compares pinned volume identities before a running image can be staged safely.
func (r *Root) SameVolume(other *Root) bool { return r.volume == other.volume }

// MoveTo renames a verified file into another pinned root without copying across volumes.
// Running images can be renamed even when their mapped executable prevents deletion.
func (r *Root) MoveTo(name string, destination *Root, target string, policy Policy) error {
	h, err := relativeOpen(r.Handle(), name, windows.DELETE|windows.FILE_GENERIC_READ, windows.FILE_OPEN, false, nil, windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	if _, err := inspect(h, false, &r.volume); err != nil {
		return err
	}
	if err := CheckSecurity(h, policy, false); err != nil {
		return err
	}
	if r.volume != destination.volume {
		return errors.New("winfs: running image staging must be on the installation volume")
	}
	return destination.rename(h, target, false)
}
