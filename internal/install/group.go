//go:build darwin || linux

package install

import (
	"context"
	"errors"
	"fmt"
	"os/user"
	"strconv"
	"strings"
)

// errGroupAbsent distinguishes a missing group from an inaccessible or malformed
// account database. Only absence authorizes creating or skipping removal of a group.
var errGroupAbsent = errors.New("fortix group does not exist")

// groupID resolves fortix through an injected lookup, macOS account services or
// Linux NSS via getent. Cancellation, malformed output and lookup failures remain
// errors; getent exit status 2 alone denotes an absent Linux group.
func (i *installer) groupID(ctx context.Context) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if i.options.GroupID != nil {
		return i.options.GroupID("fortix")
	}
	if i.options.Platform == "darwin" {
		gid, err := lookupGroup("fortix")
		var missing user.UnknownGroupError
		if errors.As(err, &missing) {
			return 0, errGroupAbsent
		}
		return gid, err
	}
	out, err := i.options.Runner.Run(ctx, "/usr/bin/getent", "group", "fortix")
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	if err != nil {
		var exit interface{ ExitCode() int }
		if errors.As(err, &exit) && exit.ExitCode() == 2 {
			return 0, errGroupAbsent
		}
		return 0, fmt.Errorf("getent group fortix: %w: %s", err, out)
	}
	return parseGroup(out)
}

// parseGroup decodes one getent group record for fortix and returns its numeric
// GID. Empty, multiline, mismatched or malformed records cannot assign ownership.
func parseGroup(out string) (int, error) {
	fields := strings.Split(strings.TrimSuffix(out, "\n"), ":")
	if len(fields) != 4 || fields[0] != "fortix" || strings.ContainsAny(strings.Join(fields, ""), "\n\r\x00") {
		return 0, errors.New("invalid fortix group record")
	}
	gid, err := strconv.ParseUint(fields[2], 10, 32)
	if err != nil || gid == 0xffffffff {
		return 0, errors.New("invalid group ID")
	}
	return int(gid), nil
}
