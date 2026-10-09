package install

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/winfs"
)

// recoverIncomplete compensates only recorded resources after native identity and ACL validation.
// The record survives any failure so another uninstall can retry without guessing ownership.
func recoverIncomplete(ctx context.Context, p paths.Paths, dataPath string, root, dataRoot *winfs.Root, service windows.Handle, manifest installManifest, policy, private winfs.Policy, ops installOps) error {
	owned := make(map[string]bool)
	privatePaths := map[string]string{filepath.Base(p.Profiles): p.Profiles, filepath.Base(p.State): p.State, filepath.Base(p.Logs): p.Logs}
	// Validate the entire ledger before touching anything; resource names never become arbitrary paths.
	for _, resource := range manifest.Created {
		switch resource {
		case "service", "group", "binary-directory", "data-directory", "file:fortix.exe", "file:fortix-helper.exe", "file:FortixApp.exe", "file:wintun.dll":
		default:
			if sid, ok := strings.CutPrefix(resource, "member:"); ok {
				if _, err := windows.StringToSid(sid); err != nil {
					return err
				}
			} else if _, ok := privatePaths[resource]; !ok {
				return errors.New("incomplete installation has an unknown resource")
			}
		}
		owned[resource] = true
	}
	if service != 0 {
		if !owned["service"] {
			return errors.New("incomplete installation does not own the existing service")
		}
		if err := ops.stopService(ctx, service); err != nil {
			return err
		}
		if err := ops.deleteService(service); err != nil {
			return err
		}
	}
	// Service deletion precedes file cleanup even if a partially written ledger was out of order.
	for i := len(manifest.Created) - 1; i >= 0; i-- {
		resource := manifest.Created[i]
		if err := ctx.Err(); err != nil {
			return err
		}
		var err error
		switch {
		case resource == "service", resource == "data-directory":
			continue
		case strings.HasPrefix(resource, "file:"):
			if root != nil {
				err = ops.removeProtected(root, p.BinaryDir, strings.TrimPrefix(resource, "file:"), policy)
			}
		case resource == "binary-directory":
			if root != nil {
				if err = ops.closeRoot(root); err != nil {
					return err
				}
				err = ops.removeDirectory(p.BinaryDir)
			}
		case resource == "group":
			err = ops.deleteGroup()
		case strings.HasPrefix(resource, "member:"):
			// Deleting the owned group removes its members and remains safe to retry after deletion.
			if !owned["group"] {
				user, _ := windows.StringToSid(strings.TrimPrefix(resource, "member:"))
				_, err = ops.changeMember(user, false)
			}
		default:
			err = ops.removePrivateTree(privatePaths[resource], private)
		}
		if err != nil && !winfs.IsNotExist(err) {
			return err
		}
	}
	if owned["data-directory"] {
		entries, err := ops.readDirectory(dataPath)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.Name() != "install.json" {
				return errors.New("unrecognized state retained during recovery")
			}
		}
	}
	// Keep a recoverable empty ledger if the final directory cannot yet be removed.
	manifest.Created = nil
	if owned["data-directory"] {
		manifest.Created = []string{"data-directory"}
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if err = ops.saveManifest(dataRoot, ctx, "install.json", data, private); err != nil {
		return err
	}
	if err = ops.removeProtected(dataRoot, dataPath, "install.json", private); err != nil {
		return err
	}
	if owned["data-directory"] {
		if err = ops.closeRoot(dataRoot); err != nil {
			return err
		}
		return ops.removeDirectory(dataPath)
	}
	return nil
}
