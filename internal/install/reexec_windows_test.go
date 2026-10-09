package install

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/winfs"
)

// TestReexecUninstall verifies argument preservation, bounded waiting and exact exit propagation.
func TestReexecUninstall(t *testing.T) {
	for _, code := range []int{0, 7, 23} {
		t.Run(string(rune('a'+code)), func(t *testing.T) {
			original := `C:\Program Files\Fortix\fortix-helper.exe`
			copy := `C:\ProgramData\Fortix\staging\fixture\fortix-helper.exe`
			args := []string{"uninstall", "--purge"}
			var events []string
			in := strings.NewReader("input")
			out, diagnostics := &strings.Builder{}, &strings.Builder{}
			ops := reexecOps{
				stage: func(ctx context.Context, image string) (string, func() error, error) {
					if image != original || ctx.Err() != nil {
						t.Fatal("incorrect staging input")
					}
					events = append(events, "stage")
					return copy, func() error { events = append(events, "cleanup"); return nil }, nil
				},
				run: func(ctx context.Context, image string, argv []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
					events = append(events, "run")
					deadline, bounded := ctx.Deadline()
					if !bounded || time.Until(deadline) > 5*time.Minute || image != copy || stdin != in || stdout != out || stderr != diagnostics {
						t.Fatal("unbounded child or changed stream/image")
					}
					if !reflect.DeepEqual(argv, []string{"uninstall", "--purge", "--uninstall-original", original}) {
						t.Fatalf("child args: %v", argv)
					}
					return code, nil
				},
			}
			err := reexecUninstall(context.Background(), original, args, in, out, diagnostics, ops)
			var exit *ExitError
			if code == 0 && err != nil || code != 0 && (!errors.As(err, &exit) || exit.Code != code) {
				t.Fatalf("exit %d: %v", code, err)
			}
			if !reflect.DeepEqual(events, []string{"stage", "run", "cleanup"}) || !reflect.DeepEqual(args, []string{"uninstall", "--purge"}) {
				t.Fatalf("ordering/input mutation: %v %v", events, args)
			}
		})
	}
}

// TestReexecFailures rejects unverified staging and retains launch, cancellation and cleanup failures.
func TestReexecFailures(t *testing.T) {
	stageFailure := errors.New("hash mismatch")
	launchFailure := errors.New("launch denied")
	cleanupFailure := errors.New("deferred deletion failed")
	for _, stageFails := range []bool{false, true} {
		called, cleaned := false, false
		ops := reexecOps{
			stage: func(context.Context, string) (string, func() error, error) {
				if stageFails {
					return "", nil, stageFailure
				}
				return "copy", func() error { cleaned = true; return cleanupFailure }, nil
			},
			run: func(context.Context, string, []string, io.Reader, io.Writer, io.Writer) (int, error) {
				called = true
				return 0, launchFailure
			},
		}
		err := reexecUninstall(context.Background(), "original", []string{"uninstall"}, nil, io.Discard, io.Discard, ops)
		if stageFails {
			if !errors.Is(err, stageFailure) || called || cleaned {
				t.Fatalf("ran an unverified image: %v", err)
			}
		} else if !errors.Is(err, launchFailure) || !errors.Is(err, cleanupFailure) || !called || !cleaned {
			t.Fatalf("lost launch/cleanup failure: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := reexecUninstall(ctx, "original", []string{"uninstall"}, nil, io.Discard, io.Discard, reexecOps{
		stage: func(ctx context.Context, _ string) (string, func() error, error) { return "", nil, ctx.Err() },
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation: %v", err)
	}
}

// TestReexecCancellation preserves the cancellation cause, child status and cleanup after waiting.
func TestReexecCancellation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		deadline bool
		cause    error
	}{
		{name: "interrupt", cause: context.Canceled},
		{name: "timeout", deadline: true, cause: context.DeadlineExceeded},
	} {
		for _, status := range []struct {
			name string
			code int
		}{
			{name: "success", code: 0},
			{name: "failure", code: 23},
		} {
			t.Run(tc.name+"/"+status.name, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				if tc.deadline {
					cancel()
					ctx, cancel = context.WithTimeout(context.Background(), 10*time.Millisecond)
				}
				defer cancel()
				var events []string
				ops := reexecOps{
					stage: func(context.Context, string) (string, func() error, error) {
						events = append(events, "stage")
						return "copy", func() error { events = append(events, "cleanup"); return nil }, nil
					},
					run: func(ctx context.Context, _ string, _ []string, _ io.Reader, _, _ io.Writer) (int, error) {
						events = append(events, "run")
						if !tc.deadline {
							cancel()
						}
						<-ctx.Done()
						if !errors.Is(ctx.Err(), tc.cause) {
							t.Fatalf("child cancellation cause: %v", ctx.Err())
						}
						return status.code, nil
					},
				}
				err := reexecUninstall(ctx, "original", []string{"uninstall"}, nil, io.Discard, io.Discard, ops)
				var exit *ExitError
				if !errors.Is(err, tc.cause) || !strings.Contains(err.Error(), tc.cause.Error()) {
					t.Fatalf("lost cancellation cause: %v", err)
				}
				if status.code != 0 && (!errors.As(err, &exit) || exit.Code != status.code) || status.code == 0 && errors.As(err, &exit) {
					t.Fatalf("changed child exit status: %v", err)
				}
				if !reflect.DeepEqual(events, []string{"stage", "run", "cleanup"}) {
					t.Fatalf("cleanup before child exit: %v", events)
				}
			})
		}
	}
}

// TestUninstallInternalPaths rejects caller TEMP, recursive installed execution and path aliases.
func TestUninstallInternalPaths(t *testing.T) {
	installed := `C:\Program Files\Fortix\fortix-helper.exe`
	for _, o := range []Options{
		{Helper: installed, Original: installed},
		{Helper: `C:\Temp\fortix-helper.exe`, Original: installed},
		{Helper: `C:\ProgramData\Fortix\staging\not-a-guid\fortix-helper.exe`, Original: installed},
		{Helper: `C:\ProgramData\Fortix\staging\not-a-guid\fortix-helper.exe`, Original: `C:\Temp\original.exe`},
	} {
		if root, err := openUninstallStage(o, `C:\ProgramData\Fortix`, installed); err == nil || root != nil {
			t.Fatalf("unsafe internal handoff accepted: %+v", o)
		}
	}
}

// TestUninstallCopyHash rejects absent, truncated and altered copied executables.
func TestUninstallCopyHash(t *testing.T) {
	original := []byte("verified executable fixture")
	for _, copy := range [][]byte{nil, {}, []byte("verified executable"), []byte("altered executable fixture")} {
		if verifyUninstallCopy(copy, original) == nil {
			t.Fatal("unverified executable copy accepted")
		}
	}
	if err := verifyUninstallCopy(append([]byte(nil), original...), original); err != nil {
		t.Fatal(err)
	}
	if verifyUninstallCopy(original, nil) == nil {
		t.Fatal("absent original accepted")
	}
}

// TestStagedRemovalOrdering proves the mapped parent is renamed after stop, never deleted in place.
func TestStagedRemovalOrdering(t *testing.T) {
	f := newTransactionFixture(t, false, 0)
	if err := f.run(); err != nil {
		t.Fatal(err)
	}
	ops := f.removalOperations()
	stage := new(winfs.Root)
	moved := false
	ops = stagedRemoval(ops, stage, func(root *winfs.Root, source string, destination *winfs.Root, target string, _ winfs.Policy) error {
		if f.running || source != "fortix-helper.exe" || destination != stage || target != "original.exe" || f.roots[root] != f.p.BinaryDir {
			t.Fatal("mapped image moved before shutdown or to wrong destination")
		}
		moved = true
		delete(f.files, filepath.Join(f.p.BinaryDir, source))
		return nil
	})
	if err := f.remove(true, ops); err != nil {
		t.Fatal(err)
	}
	if !moved || f.service || f.dirs[f.p.BinaryDir] || f.group {
		t.Fatal("staged removal did not complete")
	}
}

// TestStagedPurge retains only staging and queues directory deletion after private data cleanup.
func TestStagedPurge(t *testing.T) {
	f := newTransactionFixture(t, false, 0)
	if err := f.run(); err != nil {
		t.Fatal(err)
	}
	var scheduled []string
	ops := stagedPurge(f.removalOperations(), f.data, func(path string) error {
		scheduled = append(scheduled, path)
		return nil
	})
	if err := f.remove(true, ops); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(scheduled, []string{filepath.Join(f.data, "staging"), f.data}) || f.group || f.service || f.dirs[f.p.BinaryDir] {
		t.Fatalf("incorrect staged purge: %v", scheduled)
	}
	for _, path := range []string{f.p.Profiles, f.p.State, f.p.Logs} {
		if f.dirs[path] {
			t.Fatalf("private data retained: %s", path)
		}
	}
}

// TestStagedArguments preserves the flag terminator without hiding the internal handoff.
func TestStagedArguments(t *testing.T) {
	original := `C:\Program Files\Fortix\fortix-helper.exe`
	args := []string{"uninstall", "--purge=false", "--"}
	got := stagedArguments(args, original)
	want := []string{"uninstall", "--purge=false", "--uninstall-original", original, "--"}
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(args, []string{"uninstall", "--purge=false", "--"}) {
		t.Fatalf("terminator/input mutation: %v %v", got, args)
	}
}
