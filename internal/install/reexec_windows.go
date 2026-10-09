package install

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/sys/windows"

	"github.com/avhn/fortix/internal/winfs"
)

// ExitError preserves the staged helper's exact exit status without retaining arguments.
type ExitError struct{ Code int }

// Error reports only the child status, never installation arguments or user data.
func (e *ExitError) Error() string {
	return fmt.Sprintf("staged uninstall exited with status %d", e.Code)
}

// reexecOps injects staging and child execution so tests never install machine resources.
type reexecOps struct {
	stage func(context.Context, string) (string, func() error, error)
	run   func(context.Context, string, []string, io.Reader, io.Writer, io.Writer) (int, error)
}

// RunUninstall moves execution out of ProgramFiles while preserving all accepted arguments.
// Protected ProgramData is preferred to TEMP because ordinary users cannot replace its ancestors.
func RunUninstall(ctx context.Context, o Options, args []string, in io.Reader, out, diagnostics io.Writer) error {
	if o.Original != "" {
		return Uninstall(ctx, o)
	}
	p, _, err := machinePaths()
	if err != nil {
		return err
	}
	if !equalPath(o.Helper, filepath.Join(p.BinaryDir, "fortix-helper.exe")) {
		return Uninstall(ctx, o)
	}
	if err := requireElevation(); err != nil {
		return err
	}
	return reexecUninstall(ctx, o.Helper, args, in, out, diagnostics, reexecOps{stage: stageUninstaller, run: runStagedUninstaller})
}

// reexecUninstall bounds the child wait and joins cleanup errors without losing its exit status.
func reexecUninstall(ctx context.Context, original string, args []string, in io.Reader, out, diagnostics io.Writer, ops reexecOps) (result error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	copy, cleanup, err := ops.stage(ctx, original)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, cleanup()) }()
	childArgs := stagedArguments(args, original)
	code, err := ops.run(ctx, copy, childArgs, in, out, diagnostics)
	// Retain the cancellation cause even when the child returns only an exit status.
	err = errors.Join(err, ctx.Err())
	if code != 0 {
		err = errors.Join(&ExitError{Code: code}, err)
	}
	return err
}

// stagedArguments preserves accepted flags, placing the handoff before a trailing flag terminator.
func stagedArguments(args []string, original string) []string {
	child := append([]string(nil), args...)
	terminated := len(child) > 0 && child[len(child)-1] == "--"
	if terminated {
		child = child[:len(child)-1]
	}
	child = append(child, "--uninstall-original", original)
	if terminated {
		child = append(child, "--")
	}
	return child
}

// runStagedUninstaller inherits only explicit standard streams and never searches PATH.
// A neutral working directory prevents loading files from the original release directory.
// Console interrupts already reach the child; cancellation allows bounded rollback before killing it.
func runStagedUninstaller(ctx context.Context, image string, args []string, in io.Reader, out, diagnostics io.Writer) (int, error) {
	cmd := exec.CommandContext(ctx, image, args...)
	cmd.Cancel = func() error { return nil }
	cmd.WaitDelay = 2 * time.Minute
	cmd.Dir = filepath.Dir(image)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, diagnostics
	err := cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	return 0, err
}

// stageUninstaller creates a fresh SYSTEM-owned leaf and verifies the published copy's hash.
// The parent pins staging until the child exits; queued deletion also covers launch failure.
func stageUninstaller(ctx context.Context, original string) (image string, cleanup func() error, result error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	restore, err := enableRestore()
	if err != nil {
		return "", nil, err
	}
	defer func() {
		result = errors.Join(result, restore())
		if result != nil && cleanup != nil {
			result = errors.Join(result, cleanup())
			cleanup = nil
		}
	}()
	p, dataPath, err := machinePaths()
	if err != nil {
		return "", nil, err
	}
	policy, err := binaryPolicy()
	if err != nil {
		return "", nil, err
	}
	private, err := winfs.SystemPolicy(nil, 0)
	if err != nil {
		return "", nil, err
	}
	binary, err := winfs.SecureDirectory(p.BinaryDir, policy)
	if err != nil {
		return "", nil, err
	}
	defer binary.Close()
	bytes, exists, err := protectedBytes(binary, "fortix-helper.exe", policy)
	if err != nil || !exists || len(bytes) == 0 {
		return "", nil, errors.Join(err, errors.New("installed helper is missing or unreadable"))
	}
	data, err := winfs.SecureDirectory(dataPath, private)
	if err != nil {
		return "", nil, err
	}
	defer data.Close()
	staging, err := winfs.SecureDirectory(filepath.Join(dataPath, "staging"), private)
	if err != nil {
		return "", nil, err
	}
	defer staging.Close()
	id, err := windows.GenerateGUID()
	if err != nil {
		return "", nil, err
	}
	directory := filepath.Join(dataPath, "staging", id.String())
	root, created, err := createDirectory(directory, private)
	if err != nil {
		return "", nil, err
	}
	if !created {
		_ = root.Close()
		return "", nil, errors.New("uninstall staging directory already exists")
	}
	image = filepath.Join(directory, "fortix-helper.exe")
	cleanup = func() error {
		return errors.Join(root.Close(), scheduleDeletion(image), scheduleDeletion(filepath.Join(directory, "original.exe")), scheduleDeletion(directory), scheduleDeletion(filepath.Dir(directory)))
	}
	if !binary.SameVolume(root) {
		return "", nil, errors.Join(errors.New("installed-image uninstall requires ProgramData and ProgramFiles on the same volume; run the release-directory helper instead"), cleanup())
	}
	if err := publish(ctx, root, directory, "fortix-helper.exe", bytes, private); err != nil {
		return "", nil, errors.Join(err, cleanup())
	}
	return image, cleanup, nil
}

// openUninstallStage rejects forged internal flags and verifies both images before mutation.
// An absent original, cross-volume staging or changed hash is not permission to remove resources.
func openUninstallStage(o Options, dataPath, installed string) (*winfs.Root, error) {
	if !equalPath(o.Original, installed) || equalPath(o.Helper, installed) {
		return nil, errors.New("invalid staged uninstall original path")
	}
	directory := filepath.Dir(o.Helper)
	if !equalPath(filepath.Dir(directory), filepath.Join(dataPath, "staging")) || !equalPath(o.Helper, filepath.Join(directory, "fortix-helper.exe")) {
		return nil, errors.New("uninstall copy must be in protected machine staging")
	}
	id, err := windows.GUIDFromString(filepath.Base(directory))
	if err != nil || id.String() != filepath.Base(directory) {
		return nil, errors.New("uninstall staging directory must have a fresh identity")
	}
	private, err := winfs.SystemPolicy(nil, 0)
	if err != nil {
		return nil, err
	}
	root, err := winfs.SecureDirectory(directory, private)
	if err != nil {
		return nil, err
	}
	copy, exists, err := protectedBytes(root, "fortix-helper.exe", private)
	original, readErr := sourceBytes(installed)
	if err != nil || readErr != nil || !exists || verifyUninstallCopy(copy, original) != nil {
		_ = root.Close()
		return nil, errors.Join(err, readErr, errors.New("staged uninstall image hash mismatch"))
	}
	return root, nil
}

// verifyUninstallCopy accepts only a nonempty byte-identical copy of the installed helper.
func verifyUninstallCopy(copy, original []byte) error {
	if len(copy) == 0 || len(original) == 0 || sha256.Sum256(copy) != sha256.Sum256(original) {
		return errors.New("staged uninstall image hash mismatch")
	}
	return nil
}

// stagedRemoval renames the waiting parent's mapped image only after verified service shutdown.
// Same-volume, handle-relative rename leaves ProgramFiles removable without executing from TEMP.
func stagedRemoval(ops installOps, stage *winfs.Root, move func(*winfs.Root, string, *winfs.Root, string, winfs.Policy) error) installOps {
	remove := ops.removeProtected
	ops.removeProtected = func(root *winfs.Root, directory, name string, policy winfs.Policy) error {
		if name == "fortix-helper.exe" {
			return move(root, name, stage, "original.exe", policy)
		}
		return remove(root, directory, name, policy)
	}
	return ops
}

// stagedPurge leaves only verified staging images for reboot while removing user data immediately.
// This also supports a release-directory purge following an earlier installed-image uninstall.
func stagedPurge(ops installOps, dataPath string, schedule func(string) error) installOps {
	read := ops.readDirectory
	ops.readDirectory = func(path string) ([]os.DirEntry, error) {
		entries, err := read(path)
		if err != nil || !equalPath(path, dataPath) {
			return entries, err
		}
		filtered := make([]os.DirEntry, 0, len(entries))
		for _, entry := range entries {
			if entry.Name() != "staging" {
				filtered = append(filtered, entry)
			}
		}
		return filtered, nil
	}
	remove := ops.removeDirectory
	ops.removeDirectory = func(path string) error {
		if equalPath(path, dataPath) {
			return errors.Join(schedule(filepath.Join(dataPath, "staging")), schedule(dataPath))
		}
		return remove(path)
	}
	return ops
}

// scheduleDeletion removes only a previously verified local staging path at the next reboot.
func scheduleDeletion(path string) error {
	if !winfs.ValidPath(path) {
		return errors.New("invalid deferred deletion path")
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(name, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
}
