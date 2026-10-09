package install

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/winfs"
)

// TestStopServiceFailureCodes distinguishes old crashes from failed cleanup during this call.
func TestStopServiceFailureCodes(t *testing.T) {
	for _, state := range []uint32{windows.SERVICE_STOPPED, windows.SERVICE_RUNNING, windows.SERVICE_START_PENDING, windows.SERVICE_STOP_PENDING} {
		for _, specific := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/specific=%v", state, specific), func(t *testing.T) {
				status := windows.SERVICE_STATUS{CurrentState: state, Win32ExitCode: 1}
				if specific {
					status.Win32ExitCode = uint32(windows.ERROR_SERVICE_SPECIFIC_ERROR)
					status.ServiceSpecificExitCode = 1
				}
				controls, waits := 0, 0
				ops := serviceStopOps{
					query: func(windows.Handle) (windows.SERVICE_STATUS, error) { return status, nil },
					control: func(_ windows.Handle, command uint32, _ *windows.SERVICE_STATUS) error {
						if command != windows.SERVICE_CONTROL_STOP {
							t.Fatal(command)
						}
						controls++
						return nil
					},
					wait: func(context.Context, windows.Handle, uint32) error {
						waits++
						status.CurrentState = windows.SERVICE_STOPPED
						return nil
					},
				}
				err := stopServiceWith(t.Context(), 1, ops)
				if (err == nil) != (state == windows.SERVICE_STOPPED) {
					t.Fatalf("state %d: %v", state, err)
				}
				wantControls, wantWaits := 1, 1
				if state == windows.SERVICE_STOPPED {
					wantControls, wantWaits = 0, 0
				}
				if state == windows.SERVICE_STOP_PENDING {
					wantControls = 0
				}
				if controls != wantControls || waits != wantWaits {
					t.Fatalf("controls=%d waits=%d", controls, waits)
				}
			})
		}
	}
}

// TestPurgeGroupOwnership preserves adopted aliases and unrelated memberships.
func TestPurgeGroupOwnership(t *testing.T) {
	for _, owned := range []bool{false, true} {
		t.Run(fmt.Sprint(owned), func(t *testing.T) {
			manifest := installManifest{Created: []string{"member:S-1-5-21-1-2-3-1001", "file:fortix.exe"}}
			if owned {
				manifest.Created = append(manifest.Created, "group")
			}
			deleted := false
			var removed []string
			err := purgeGroup(manifest, func() error { deleted = true; return nil }, func(sid *windows.SID, add bool) (bool, error) {
				if add {
					t.Fatal("purge enrolled a member")
				}
				removed = append(removed, sid.String())
				return true, nil
			})
			if err != nil || deleted != owned {
				t.Fatalf("deleted=%v: %v", deleted, err)
			}
			if owned && len(removed) != 0 || !owned && !reflect.DeepEqual(removed, []string{"S-1-5-21-1-2-3-1001"}) {
				t.Fatal(removed)
			}
		})
	}
}

// transactionFixture models protected resources while exercising the production transaction body.
// Every compensation is checked against a mutation ledger, and final state against the original snapshot.
type transactionFixture struct {
	t                               *testing.T
	update                          bool
	failAt                          int
	steps                           []string
	failed                          bool
	undo                            []string
	roots                           map[*winfs.Root]string
	dirs                            map[string]bool
	files                           map[string]string
	originalFiles                   map[string]string
	group, member, service, running bool
	manifestRegistered              bool
	p                               paths.Paths
	data                            string
}

// newTransactionFixture seeds unrelated resources and, for updates, the exact prior manifest and payloads.
func newTransactionFixture(t *testing.T, update bool, failAt int) *transactionFixture {
	f := &transactionFixture{t: t, update: update, failAt: failAt, roots: make(map[*winfs.Root]string), dirs: make(map[string]bool), files: make(map[string]string), originalFiles: make(map[string]string), data: `C:\Data\Fortix`}
	f.p = paths.Paths{BinaryDir: `C:\Programs\Fortix`, Profiles: filepath.Join(f.data, "profiles"), State: filepath.Join(f.data, "state"), Logs: filepath.Join(f.data, "logs")}
	f.files["unrelated"] = "leave alone"
	if update {
		f.group, f.member, f.service, f.running = true, true, true, true
		for _, dir := range []string{f.data, f.p.BinaryDir, f.p.Profiles, f.p.State, f.p.Logs} {
			f.dirs[dir] = true
		}
		data, err := json.Marshal(installManifest{Version: 1, UUID: "original", Complete: true, Created: []string{"member:S-1-5-21-1-2-3-1001"}, Hashes: map[string]string{"fortix.exe": "old-hash"}})
		if err != nil {
			t.Fatal(err)
		}
		f.files[filepath.Join(f.data, "install.json")] = string(data)
		for _, name := range []string{"fortix-helper.exe", "fortix.exe"} {
			f.files[filepath.Join(f.p.BinaryDir, name)] = "old:" + name
		}
	}
	for name, data := range f.files {
		f.originalFiles[name] = data
	}
	return f
}

// step fails exactly one forward operation; rollback calls cannot consume another failure.
func (f *transactionFixture) step(name string) error {
	f.steps = append(f.steps, name)
	if len(f.steps) == f.failAt {
		f.failed = true
		return errors.New("injected " + name)
	}
	return nil
}

// compensate verifies strict reverse order, including restoration rather than deletion on updates.
func (f *transactionFixture) compensate(name string) {
	f.t.Helper()
	if len(f.undo) == 0 || f.undo[len(f.undo)-1] != name {
		f.t.Fatalf("undo %q, pending %v", name, f.undo)
	}
	f.undo = f.undo[:len(f.undo)-1]
}

// operations substitutes machine effects, leaving stage selection and rollback registration in production code.
func (f *transactionFixture) operations() installOps {
	return installOps{
		createDirectory: func(path string, _ winfs.Policy) (*winfs.Root, bool, error) {
			if err := f.step("directory:" + path); err != nil {
				return nil, false, err
			}
			created := !f.dirs[path]
			f.dirs[path] = true
			if created {
				f.undo = append(f.undo, "directory:"+path)
			}
			root := new(winfs.Root)
			f.roots[root] = path
			return root, created, nil
		},
		closeRoot:       func(*winfs.Root) error { return nil },
		removeDirectory: func(path string) error { f.compensate("directory:" + path); delete(f.dirs, path); return nil },
		removePrivateTree: func(path string, _ winfs.Policy) error {
			f.compensate("directory:" + path)
			delete(f.dirs, path)
			return nil
		},
		protectedBytes: func(root *winfs.Root, name string, _ winfs.Policy) ([]byte, bool, error) {
			data, exists := f.files[filepath.Join(f.roots[root], name)]
			return []byte(data), exists, nil
		},
		saveManifest: func(root *winfs.Root, _ context.Context, name string, data []byte, _ winfs.Policy) error {
			key := filepath.Join(f.roots[root], name)
			if f.failed {
				f.compensate("manifest")
				f.files[key] = string(data)
				return nil
			}
			if !f.manifestRegistered {
				f.undo = append(f.undo, "manifest")
				f.manifestRegistered = true
			}
			f.files[key] = string(data)
			return f.step("manifest")
		},
		removeProtected: func(_ *winfs.Root, directory, name string, _ winfs.Policy) error {
			if name == "install.json" {
				f.compensate("manifest")
			} else {
				f.compensate("file:" + name)
			}
			delete(f.files, filepath.Join(directory, name))
			return nil
		},
		publish: func(_ context.Context, _ *winfs.Root, directory, name string, data []byte, _ winfs.Policy) error {
			f.files[filepath.Join(directory, name)] = string(data)
			if f.failed {
				f.compensate("file:" + name)
				return nil
			}
			f.undo = append(f.undo, "file:"+name)
			return f.step("publish:" + name)
		},
		ensureGroup: func() (bool, error) {
			created := !f.group
			f.group = true
			if created {
				f.undo = append(f.undo, "group")
			}
			return created, f.step("group")
		},
		deleteGroup: func() error { f.compensate("group"); f.group = false; return nil },
		changeMember: func(_ *windows.SID, add bool) (bool, error) {
			if !add {
				f.compensate("member")
				f.member = false
				return true, nil
			}
			if err := f.step("member"); err != nil {
				return false, err
			}
			added := !f.member
			f.member = true
			if added {
				f.undo = append(f.undo, "member")
			}
			return added, nil
		},
		createService: func(windows.Handle, string) (windows.Handle, error) {
			if err := f.step("create-service"); err != nil {
				return 0, err
			}
			f.service = true
			f.undo = append(f.undo, "service")
			return 2, nil
		},
		configureService: func(windows.Handle) error { return f.step("configure-service") },
		deleteService:    func(windows.Handle) error { f.compensate("service"); f.service = false; return nil },
		closeService:     func(windows.Handle) error { return nil },
		startService: func(context.Context, windows.Handle) error {
			f.running = true
			if f.failed {
				f.compensate("restart")
				return nil
			}
			f.undo = append(f.undo, "stop")
			return f.step("start-service")
		},
		stopService: func(context.Context, windows.Handle) error {
			if f.failed {
				f.compensate("stop")
				f.running = false
				return nil
			}
			if err := f.step("stop-service"); err != nil {
				return err
			}
			f.running = false
			f.undo = append(f.undo, "restart")
			return nil
		},
	}
}

// run invokes the same transaction used by Install after its native preflight checks.
func (f *transactionFixture) run() error {
	user, err := windows.StringToSid("S-1-5-21-1-2-3-1001")
	if err != nil {
		f.t.Fatal(err)
	}
	var service windows.Handle
	if f.update {
		service = 1
	}
	return installResources(f.t.Context(), f.p, f.data, map[string][]byte{"fortix.exe": []byte("new cli"), "fortix-helper.exe": []byte("new helper")}, user, winfs.Policy{}, winfs.Policy{}, 1, service, f.update, f.operations())
}

// TestInstallStageFailures injects each actual mutation stage, including every progress-manifest save.
// Fresh installs must leave nothing owned; updates must restore prior bytes, metadata and running state.
func TestInstallStageFailures(t *testing.T) {
	for _, update := range []bool{false, true} {
		t.Run(fmt.Sprintf("update=%v", update), func(t *testing.T) {
			baseline := newTransactionFixture(t, update, 0)
			if err := baseline.run(); err != nil {
				t.Fatal(err)
			}
			for index, stage := range baseline.steps {
				t.Run(fmt.Sprintf("%02d-%s", index+1, stage), func(t *testing.T) {
					f := newTransactionFixture(t, update, index+1)
					err := f.run()
					if err == nil || !f.failed {
						t.Fatalf("failure not reached: %v", err)
					}
					if len(f.undo) != 0 {
						t.Fatalf("uncompensated: %v; %v", f.undo, err)
					}
					if !reflect.DeepEqual(f.files, f.originalFiles) {
						t.Fatalf("files not restored: %v, want %v", f.files, f.originalFiles)
					}
					if f.group != update || f.member != update || f.service != update || f.running != update {
						t.Fatalf("resources changed: group=%v member=%v service=%v running=%v", f.group, f.member, f.service, f.running)
					}
					wantDirs := 0
					if update {
						wantDirs = 5
					}
					if len(f.dirs) != wantDirs {
						t.Fatalf("directories changed: %v", f.dirs)
					}
				})
			}
		})
	}
}

// removalOperations models idempotent native removal separately from the rollback-order assertions.
func (f *transactionFixture) removalOperations() installOps {
	ops := f.operations()
	ops.removeDirectory = func(path string) error { delete(f.dirs, path); return nil }
	ops.removePrivateTree = func(path string, _ winfs.Policy) error {
		delete(f.dirs, path)
		for name := range f.files {
			if strings.HasPrefix(name, path+string(filepath.Separator)) {
				delete(f.files, name)
			}
		}
		return nil
	}
	ops.removeProtected = func(_ *winfs.Root, directory, name string, _ winfs.Policy) error {
		delete(f.files, filepath.Join(directory, name))
		return nil
	}
	ops.deleteGroup = func() error { f.group, f.member = false, false; return nil }
	ops.changeMember = func(_ *windows.SID, add bool) (bool, error) { f.member = add; return true, nil }
	ops.deleteService = func(windows.Handle) error { f.service = false; return nil }
	ops.stopService = func(context.Context, windows.Handle) error { f.running = false; return nil }
	ops.queryService = func(windows.Handle) (windows.SERVICE_STATUS, error) {
		state := uint32(windows.SERVICE_STOPPED)
		if f.running {
			state = windows.SERVICE_RUNNING
		}
		return windows.SERVICE_STATUS{CurrentState: state}, nil
	}
	ops.readDirectory = func(string) ([]os.DirEntry, error) { return nil, nil }
	return ops
}

// remove invokes the real removal transaction with roots representing the current simulated machine.
func (f *transactionFixture) remove(purge bool, ops installOps) error {
	var root *winfs.Root
	if f.dirs[f.p.BinaryDir] {
		root = new(winfs.Root)
		f.roots[root] = f.p.BinaryDir
	}
	dataRoot := new(winfs.Root)
	f.roots[dataRoot] = f.data
	var service windows.Handle
	if f.service {
		service = 1
	}
	return uninstallResources(f.t.Context(), Options{Purge: purge}, f.p, f.data, root, dataRoot, service, winfs.Policy{}, winfs.Policy{}, ops)
}

// TestRetainedInstallationPurge keeps group ownership through plain removal and optional reinstallation.
func TestRetainedInstallationPurge(t *testing.T) {
	for _, reinstall := range []bool{false, true} {
		t.Run(fmt.Sprintf("reinstall=%v", reinstall), func(t *testing.T) {
			f := newTransactionFixture(t, false, 0)
			if err := f.run(); err != nil {
				t.Fatal(err)
			}
			if err := f.remove(false, f.removalOperations()); err != nil {
				t.Fatal(err)
			}
			var retained installManifest
			if err := json.Unmarshal([]byte(f.files[filepath.Join(f.data, "install.json")]), &retained); err != nil {
				t.Fatal(err)
			}
			if !retained.Removed || !retained.Complete || len(retained.Hashes) != 0 || !f.group || !f.member || f.service || f.dirs[f.p.BinaryDir] {
				t.Fatalf("invalid retained state: %+v", retained)
			}
			for _, resource := range retained.Created {
				if resource == "service" || resource == "binary-directory" || strings.HasPrefix(resource, "file:") {
					t.Fatalf("removed resource retained: %s", resource)
				}
			}
			if reinstall {
				if err := f.run(); err != nil {
					t.Fatal(err)
				}
			} else if err := f.remove(false, f.removalOperations()); err != nil {
				t.Fatalf("repeated removal: %v", err)
			}
			if err := f.remove(true, f.removalOperations()); err != nil {
				t.Fatal(err)
			}
			if f.group || f.member || f.service || len(f.dirs) != 0 || len(f.files) != 1 || f.files["unrelated"] != "leave alone" {
				t.Fatalf("purge left resources: %+v", f)
			}
		})
	}
}

// TestIncompleteInstallationRecovery exercises persisted progress rather than an in-memory rollback stack.
func TestIncompleteInstallationRecovery(t *testing.T) {
	for _, failStop := range []bool{false, true} {
		t.Run(fmt.Sprintf("failed-stop=%v", failStop), func(t *testing.T) {
			f := newTransactionFixture(t, false, 0)
			if err := f.run(); err != nil {
				t.Fatal(err)
			}
			key := filepath.Join(f.data, "install.json")
			var manifest installManifest
			if err := json.Unmarshal([]byte(f.files[key]), &manifest); err != nil {
				t.Fatal(err)
			}
			manifest.Complete = false
			data, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			f.files[key] = string(data)
			if failStop {
				ops := f.removalOperations()
				ops.stopService = func(context.Context, windows.Handle) error { return errors.New("cleanup failed") }
				if err := f.remove(false, ops); err == nil || f.files[key] != string(data) || !f.service || !f.group {
					t.Fatalf("failed recovery lost ownership: %v", err)
				}
			}
			if err := f.remove(false, f.removalOperations()); err != nil {
				t.Fatal(err)
			}
			if f.group || f.member || f.service || len(f.dirs) != 0 || len(f.files) != 1 {
				t.Fatalf("incomplete recovery: %+v", f)
			}
		})
	}
}

// TestRecoveryRetriesAfterGroupDeletion preserves the ledger after a later filesystem failure.
func TestRecoveryRetriesAfterGroupDeletion(t *testing.T) {
	f := newTransactionFixture(t, false, 0)
	if err := f.run(); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(f.data, "install.json")
	var manifest installManifest
	if err := json.Unmarshal([]byte(f.files[key]), &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Complete = false
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	f.files[key] = string(data)
	ops := f.removalOperations()
	ops.removePrivateTree = func(string, winfs.Policy) error { return errors.New("directory locked") }
	if err := f.remove(false, ops); err == nil || f.group || f.service || f.files[key] != string(data) {
		t.Fatalf("recovery did not retain retry state: %v", err)
	}
	if err := f.remove(false, f.removalOperations()); err != nil {
		t.Fatal(err)
	}
	if len(f.dirs) != 0 || len(f.files) != 1 {
		t.Fatalf("retry left resources: %+v", f)
	}
}

// TestRecoveryRejectsUnknownResources validates the entire ledger before stopping a service.
func TestRecoveryRejectsUnknownResources(t *testing.T) {
	f := newTransactionFixture(t, false, 0)
	if err := f.run(); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(f.data, "install.json")
	var manifest installManifest
	if err := json.Unmarshal([]byte(f.files[key]), &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Complete = false
	manifest.Created = append(manifest.Created, `file:..\unrelated.exe`)
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	f.files[key] = string(data)
	if err := f.remove(false, f.removalOperations()); err == nil || !f.service || !f.running || !f.group || f.files[key] != string(data) {
		t.Fatalf("invalid ledger mutated resources: %v", err)
	}
}
