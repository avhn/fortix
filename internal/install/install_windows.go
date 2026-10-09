// Package install manages the protected Windows helper installation with explicit elevation.
package install

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/winfs"
)

// Options selects the sibling helper payloads and explicit enrollment or purge behavior.
type Options struct {
	Helper, CLI, User string
	Purge             bool
	Original          string // Internal staged-uninstall source, validated against known folders.
}

// installManifest records resource ownership and verified content without user credentials.
type installManifest struct {
	Version  int               `json:"version"`
	UUID     string            `json:"installation_uuid"`
	Complete bool              `json:"complete"`
	Removing bool              `json:"removing,omitempty"`
	Removed  bool              `json:"removed,omitempty"`
	Created  []string          `json:"created_resources"`
	Hashes   map[string]string `json:"sha256"`
}

// rollbackStack retains compensations in mutation order and reports every failed cleanup.
type rollbackStack struct{ undo []func(context.Context) error }

// add records a compensation before the corresponding operation can partially succeed.
func (r *rollbackStack) add(undo func(context.Context) error) { r.undo = append(r.undo, undo) }

// rollback uses a fresh bounded context and stops if a compensation fails.
// This preserves the incomplete manifest and prevents deleting files while a failed stop still owns them.
func (r *rollbackStack) rollback() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for i := len(r.undo) - 1; i >= 0; i-- {
		if err := r.undo[i](ctx); err != nil {
			return fmt.Errorf("rollback incomplete, retained installation metadata: %w", err)
		}
	}
	return nil
}

// equalPath compares canonical Windows paths without accepting traversal or device aliases.
func equalPath(a, b string) bool {
	return winfs.ValidPath(a) && winfs.ValidPath(b) && strings.EqualFold(a, b)
}

// machinePaths resolves trusted known folders and refuses caller-controlled installation roots.
func machinePaths() (paths.Paths, string, error) {
	p, err := paths.Installation("windows", paths.Override{})
	return p, filepath.Dir(p.State), err
}

// Install validates sources and existing service ownership before any service interruption.
// Failed updates restore prior file bytes; failed fresh installs remove only resources this run created.
func Install(ctx context.Context, o Options) (result error) {
	if err := requireElevation(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	unlock, err := lockInstallation(ctx)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, unlock()) }()
	restore, err := enableRestore()
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, restore()) }()
	p, dataPath, err := machinePaths()
	if err != nil {
		return err
	}
	if equalPath(o.Helper, filepath.Join(p.BinaryDir, "fortix-helper.exe")) {
		return errors.New("run the new release's fortix-helper.exe from its extracted directory to update, not the installed running image")
	}
	if !equalPath(o.CLI, filepath.Join(filepath.Dir(o.Helper), "fortix.exe")) {
		return errors.New("CLI must be next to the running helper")
	}
	sources, err := binarySources(o.Helper)
	if err != nil {
		return err
	}
	user, err := selectedUser(o.User)
	if err != nil {
		return err
	}
	policy, err := binaryPolicy()
	if err != nil {
		return err
	}
	private, err := winfs.SystemPolicy(nil, 0)
	if err != nil {
		return err
	}
	api := nativeSCM{}
	manager, service, openErr := acquireService(api, true)
	if manager != 0 {
		defer windows.CloseServiceHandle(manager)
	}
	if openErr != nil && !errors.Is(openErr, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return openErr
	}
	defer func() {
		if service != 0 {
			_ = windows.CloseServiceHandle(service)
		}
	}()
	existed := service != 0
	wasRunning := false
	if existed {
		config, err := readServiceConfig(service)
		if err != nil {
			return err
		}
		if err = validateService(config, p.BinaryDir); err != nil {
			return err
		}
		if err = checkServiceSecurity(service); err != nil {
			return err
		}
		status, err := queryService(service)
		if err != nil {
			return err
		}
		wasRunning = status.CurrentState == windows.SERVICE_RUNNING
	}
	return installResources(ctx, p, dataPath, sources, user, policy, private, manager, service, wasRunning, nativeInstallOps())
}

// installResources runs the installation transaction after source, identity and service validation.
// Injected operations exercise real compensation ordering without modifying machine resources.
func installResources(ctx context.Context, p paths.Paths, dataPath string, sources map[string][]byte, user *windows.SID, policy, private winfs.Policy, manager, service windows.Handle, wasRunning bool, ops installOps) (result error) {
	existed := service != 0
	defer func() {
		if !existed && service != 0 {
			result = errors.Join(result, ops.closeService(service))
		}
	}()
	var tx rollbackStack
	var roots []*winfs.Root
	defer func() {
		for _, root := range roots {
			result = errors.Join(result, ops.closeRoot(root))
		}
	}()
	defer func() {
		if result != nil {
			result = errors.Join(result, tx.rollback())
		}
	}()
	// The parent is created first so manifest writes can describe every later resource.
	dataRoot, dataCreated, err := ops.createDirectory(dataPath, private)
	if err != nil {
		return err
	}
	roots = append(roots, dataRoot)
	if dataCreated {
		tx.add(func(context.Context) error {
			if err := ops.closeRoot(dataRoot); err != nil {
				return err
			}
			return ops.removeDirectory(dataPath)
		})
	}
	previous, hadManifest, err := ops.protectedBytes(dataRoot, "install.json", private)
	if err != nil {
		return err
	}
	var manifest installManifest
	if hadManifest {
		if err = json.Unmarshal(previous, &manifest); err != nil || manifest.Version != 1 || !manifest.Complete || manifest.Removing || (manifest.Removed && existed) {
			return errors.New("installation manifest is invalid or incomplete; run uninstall to recover")
		}
	} else {
		if existed {
			return errors.New("existing service has no installation manifest")
		}
		id, err := windows.GenerateGUID()
		if err != nil {
			return err
		}
		manifest = installManifest{Version: 1, UUID: id.String(), Hashes: make(map[string]string)}
	}
	manifest.Removed = false
	manifest.Complete = false
	if manifest.Hashes == nil {
		manifest.Hashes = make(map[string]string)
	}
	if dataCreated {
		manifest.Created = append(manifest.Created, "data-directory")
	}
	tx.add(func(ctx context.Context) error {
		if hadManifest {
			return ops.saveManifest(dataRoot, ctx, "install.json", previous, private)
		}
		return ops.removeProtected(dataRoot, dataPath, "install.json", private)
	})
	// Persist progress after each creation; unsuccessful rollback leaves an incomplete record.
	save := func() error {
		data, err := json.Marshal(manifest)
		if err != nil {
			return err
		}
		return ops.saveManifest(dataRoot, ctx, "install.json", data, private)
	}
	if err = save(); err != nil {
		return err
	}
	binaryRoot, binaryCreated, err := ops.createDirectory(p.BinaryDir, policy)
	if err != nil {
		return err
	}
	roots = append(roots, binaryRoot)
	if binaryCreated {
		tx.add(func(context.Context) error {
			if err := ops.closeRoot(binaryRoot); err != nil {
				return err
			}
			return ops.removeDirectory(p.BinaryDir)
		})
		manifest.Created = append(manifest.Created, "binary-directory")
		if err = save(); err != nil {
			return err
		}
	}
	for _, path := range []string{p.Profiles, p.State, p.Logs} {
		root, created, err := ops.createDirectory(path, private)
		if err != nil {
			return err
		}
		roots = append(roots, root)
		if created {
			tx.add(func(context.Context) error {
				if err := ops.closeRoot(root); err != nil {
					return err
				}
				return ops.removePrivateTree(path, private)
			})
			manifest.Created = append(manifest.Created, filepath.Base(path))
			if err = save(); err != nil {
				return err
			}
		}
	}
	createdGroup, err := ops.ensureGroup()
	if createdGroup {
		tx.add(func(context.Context) error { return ops.deleteGroup() })
		manifest.Created = append(manifest.Created, "group")
	}
	if err != nil {
		return err
	}
	if err = save(); err != nil {
		return err
	}
	added, err := ops.changeMember(user, true)
	if err != nil {
		return err
	}
	if added {
		tx.add(func(context.Context) error { _, err := ops.changeMember(user, false); return err })
		manifest.Created = append(manifest.Created, "member:"+user.String())
	}
	if err = save(); err != nil {
		return err
	}
	// priorFile retains verified bytes for compensation before a working service is stopped.
	type priorFile struct {
		data   []byte
		exists bool
	}
	prior := make(map[string]priorFile)
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data, exists, err := ops.protectedBytes(binaryRoot, name, policy)
		if err != nil {
			return err
		}
		prior[name] = priorFile{data, exists}
	}
	if existed {
		if err = ops.stopService(ctx, service); err != nil {
			return err
		}
		// Registered before file compensation so a previous running service restarts only after restoration.
		if wasRunning {
			tx.add(func(ctx context.Context) error { return ops.startService(ctx, service) })
		}
	}
	for _, name := range names {
		old := prior[name]
		tx.add(func(ctx context.Context) error {
			if old.exists {
				return ops.publish(ctx, binaryRoot, p.BinaryDir, name, old.data, policy)
			}
			return ops.removeProtected(binaryRoot, p.BinaryDir, name, policy)
		})
		if err = ops.publish(ctx, binaryRoot, p.BinaryDir, name, sources[name], policy); err != nil {
			return err
		}
		if !old.exists {
			manifest.Created = append(manifest.Created, "file:"+name)
		}
		manifest.Hashes[name] = fmt.Sprintf("%x", sha256.Sum256(sources[name]))
		if err = save(); err != nil {
			return err
		}
	}
	if !existed {
		service, err = ops.createService(manager, p.BinaryDir)
		if err != nil {
			return err
		}
		tx.add(func(context.Context) error {
			err := ops.deleteService(service)
			err = errors.Join(err, ops.closeService(service))
			service = 0
			return err
		})
		manifest.Created = append(manifest.Created, "service")
		if err = save(); err != nil {
			return err
		}
		if err = ops.configureService(service); err != nil {
			return err
		}
	}
	tx.add(func(ctx context.Context) error { return ops.stopService(ctx, service) })
	if err = ops.startService(ctx, service); err != nil {
		return err
	}
	manifest.Complete = true
	if err = save(); err != nil {
		return err
	}
	return nil
}

// removePrivateTree verifies every descendant before deleting private state during explicit purge.
// Reparse points and unexpected ACLs stop removal rather than crossing a storage boundary.
func removePrivateTree(path string, policy winfs.Policy) error {
	root, err := winfs.OpenRoot(path)
	if winfs.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	if err := winfs.CheckSecurity(root.Handle(), policy, true); err != nil {
		return err
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		child := filepath.Join(path, entry.Name())
		if entry.IsDir() {
			if err := removePrivateTree(child, policy); err != nil {
				return err
			}
		} else {
			if err := removeProtected(root, path, entry.Name(), policy); err != nil {
				return err
			}
		}
	}
	if err := root.Close(); err != nil {
		return err
	}
	return os.Remove(path)
}

// Uninstall stops and removes only a verified installed helper; profiles and group survive without purge.
// RunUninstall stages installed-image calls before entering this serialized removal transaction.
func Uninstall(ctx context.Context, o Options) (result error) {
	if err := requireElevation(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	unlock, err := lockInstallation(ctx)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, unlock()) }()
	// Removal rewrites SYSTEM-owned progress records just like installation.
	restore, err := enableRestore()
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, restore()) }()
	p, dataPath, err := machinePaths()
	if err != nil {
		return err
	}
	if equalPath(o.Helper, filepath.Join(p.BinaryDir, "fortix-helper.exe")) {
		return errors.New("run uninstall using fortix-helper.exe from the extracted release directory, not the installed running image")
	}
	api := nativeSCM{}
	manager, err := api.openManager(windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(manager)
	service, err := api.openService(manager, serviceQueryAccess|windows.SERVICE_START|windows.SERVICE_STOP|windows.DELETE)
	if err != nil && !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return err
	}
	if service != 0 {
		defer windows.CloseServiceHandle(service)
		config, err := readServiceConfig(service)
		if err != nil {
			return err
		}
		if err = validateService(config, p.BinaryDir); err != nil {
			return err
		}
	}
	policy, err := binaryPolicy()
	if err != nil {
		return err
	}
	private, err := winfs.SystemPolicy(nil, 0)
	if err != nil {
		return err
	}
	root, err := winfs.OpenRoot(p.BinaryDir)
	if err != nil && !winfs.IsNotExist(err) {
		return err
	}
	if root != nil {
		defer root.Close()
		if err := winfs.CheckSecurity(root.Handle(), policy, true); err != nil {
			return err
		}
	}
	dataRoot, err := winfs.OpenRoot(dataPath)
	if err != nil {
		return err
	}
	defer dataRoot.Close()
	if err := winfs.CheckSecurity(dataRoot.Handle(), private, true); err != nil {
		return err
	}
	ops := nativeInstallOps()
	if o.Original != "" {
		stage, err := openUninstallStage(o, dataPath, filepath.Join(p.BinaryDir, "fortix-helper.exe"))
		if err != nil {
			return err
		}
		if root == nil || !root.SameVolume(stage) {
			_ = stage.Close()
			return errors.New("uninstall staging must be on the installation volume")
		}
		defer func() {
			directory := filepath.Dir(o.Helper)
			result = errors.Join(result, stage.Close(), scheduleDeletion(o.Helper), scheduleDeletion(filepath.Join(directory, "original.exe")), scheduleDeletion(directory))
			if o.Purge {
				result = errors.Join(result, scheduleDeletion(filepath.Join(dataPath, "staging")), scheduleDeletion(dataPath))
			}
		}()
		ops = stagedRemoval(ops, stage, (*winfs.Root).MoveTo)
	}
	if o.Purge {
		// Earlier staged removals can still have queued images until reboot.
		// Verify the private staging root before excluding it from immediate purge.
		staging, err := winfs.OpenRoot(filepath.Join(dataPath, "staging"))
		if err != nil && !winfs.IsNotExist(err) {
			return err
		}
		if staging != nil {
			if err := winfs.CheckSecurity(staging.Handle(), private, true); err != nil {
				_ = staging.Close()
				return err
			}
			defer func() { result = errors.Join(result, staging.Close()) }()
			ops = stagedPurge(ops, dataPath, scheduleDeletion)
		}
	}
	return uninstallResources(ctx, o, p, dataPath, root, dataRoot, service, policy, private, ops)
}

// uninstallResources preserves ownership across removal and supports retry after interrupted cleanup.
// Native preflight validates roots and service identity before any injected mutation is reached.
func uninstallResources(ctx context.Context, o Options, p paths.Paths, dataPath string, root, dataRoot *winfs.Root, service windows.Handle, policy, private winfs.Policy, ops installOps) (result error) {
	data, exists, err := ops.protectedBytes(dataRoot, "install.json", private)
	if err != nil {
		return err
	}
	var manifest installManifest
	if !exists || json.Unmarshal(data, &manifest) != nil || manifest.Version != 1 {
		return errors.New("valid installation manifest required for removal")
	}
	if !manifest.Complete {
		return recoverIncomplete(ctx, p, dataPath, root, dataRoot, service, manifest, policy, private, ops)
	}
	if manifest.Removed && (service != 0 || root != nil) {
		return errors.New("retained installation has unexpected service or binaries")
	}
	if (service == 0 || root == nil) && !manifest.Removing && !manifest.Removed {
		return errors.New("service or binaries disappeared without verified shutdown; removal refused")
	}
	names := []string{"FortixApp.exe", "fortix.exe", "fortix-helper.exe", "wintun.dll"}
	payloads := make(map[string][]byte)
	for _, name := range names {
		if root == nil {
			break
		}
		file, exists, err := ops.protectedBytes(root, name, policy)
		if err != nil {
			return err
		}
		if exists && fmt.Sprintf("%x", sha256.Sum256(file)) != manifest.Hashes[name] {
			return errors.New("installed payload does not match manifest")
		}
		if exists {
			payloads[name] = file
		}
	}
	var status windows.SERVICE_STATUS
	if service != 0 {
		status, err = ops.queryService(service)
		if err != nil {
			return err
		}
		if err = ops.stopService(ctx, service); err != nil {
			return err
		}
	}
	var tx rollbackStack
	committed := false
	defer func() {
		if result != nil && !committed {
			result = errors.Join(result, tx.rollback())
		}
	}()
	if status.CurrentState == windows.SERVICE_RUNNING {
		tx.add(func(ctx context.Context) error { return ops.startService(ctx, service) })
	}
	tx.add(func(ctx context.Context) error { return ops.saveManifest(dataRoot, ctx, "install.json", data, private) })
	manifest.Removing = true
	removing, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	if err := ops.saveManifest(dataRoot, ctx, "install.json", removing, private); err != nil {
		return err
	}
	for _, name := range names {
		if root == nil {
			break
		}
		if data, exists := payloads[name]; exists {
			tx.add(func(ctx context.Context) error { return ops.publish(ctx, root, p.BinaryDir, name, data, policy) })
		}
		if err = ops.removeProtected(root, p.BinaryDir, name, policy); err != nil {
			return err
		}
	}
	// Service deletion is the commit point, after all potentially locked images are removed.
	if service != 0 {
		if err = ops.deleteService(service); err != nil {
			return err
		}
	}
	committed = true
	if root != nil {
		if err = ops.closeRoot(root); err != nil {
			return err
		}
		if err = ops.removeDirectory(p.BinaryDir); err != nil {
			return err
		}
	}
	if o.Purge {
		// Keep the removal record until every private subtree is gone, so interrupted purge can resume.
		for _, path := range []string{p.Profiles, p.State, p.Logs} {
			if err = ops.removePrivateTree(path, private); err != nil {
				return err
			}
		}
		entries, err := ops.readDirectory(dataPath)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.Name() != "install.json" {
				return errors.New("unrecognized state retained during purge")
			}
		}
		if err = purgeGroup(manifest, ops.deleteGroup, ops.changeMember); err != nil {
			return err
		}
		if err = ops.removeProtected(dataRoot, dataPath, "install.json", private); err != nil {
			return err
		}
		if err = ops.closeRoot(dataRoot); err != nil {
			return err
		}
		return ops.removeDirectory(dataPath)
	}
	manifest.Removing = false
	manifest.Removed = true
	manifest.Hashes = nil
	retained := make([]string, 0, len(manifest.Created))
	for _, resource := range manifest.Created {
		if resource != "service" && resource != "binary-directory" && !strings.HasPrefix(resource, "file:") {
			retained = append(retained, resource)
		}
	}
	manifest.Created = retained
	data, err = json.Marshal(manifest)
	if err != nil {
		return err
	}
	return ops.saveManifest(dataRoot, ctx, "install.json", data, private)
}

// purgeGroup deletes an owned alias, otherwise removes only enrollment recorded by this installation.
func purgeGroup(manifest installManifest, remove func() error, member func(*windows.SID, bool) (bool, error)) error {
	for _, resource := range manifest.Created {
		if resource == "group" {
			return remove()
		}
	}
	for _, resource := range manifest.Created {
		if sid, ok := strings.CutPrefix(resource, "member:"); ok {
			user, err := windows.StringToSid(sid)
			if err != nil {
				return err
			}
			if _, err := member(user, false); err != nil {
				return err
			}
		}
	}
	return nil
}
