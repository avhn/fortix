package helper

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
)

// Peer holds only token-derived identity; UID is a service-lifetime registry handle.
type Peer struct {
	UID, GID           uint32
	SID                string
	Privileged, Member bool
}

// Authorizer may narrow the kernel-derived access policy but cannot grant access by UID.
type Authorizer func(Peer) error

// Authorize permits LocalSystem, enabled Administrators and enabled local fortix members.
func Authorize(peer Peer) error {
	if peer.Privileged || peer.Member {
		return nil
	}
	return errors.New("peer is not authorized")
}

// sidRegistry preserves injective, never-reused SID handles for every live challenge.
type sidRegistry struct {
	mu    sync.Mutex
	ids   map[string]uint32
	limit uint32
}

// register canonicalizes a SID before assigning a bounded handle; only SYSTEM gets zero.
func (r *sidRegistry) register(sid string) (uint32, error) {
	parsed, err := windows.StringToSid(sid)
	if err != nil {
		return 0, err
	}
	canonical := parsed.String()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ids == nil {
		r.ids = map[string]uint32{}
	}
	if id, ok := r.ids[canonical]; ok {
		return id, nil
	}
	limit := r.limit
	if limit == 0 {
		limit = 4096
	}
	if uint32(len(r.ids)) >= limit {
		return 0, errors.New("identity registry exhausted")
	}
	id := uint32(len(r.ids) + 1)
	if parsed.IsWellKnown(windows.WinLocalSystemSid) {
		id = 0
	}
	r.ids[canonical] = id
	return id, nil
}

// tokenGroup copies group attributes so authorization never depends on token buffer lifetime.
type tokenGroup struct {
	sid        string
	attributes uint32
}

// tokenPeer counts enabled grants only, excluding deny-only and disabled groups.
func tokenPeer(sid, fortix string, groups []tokenGroup) Peer {
	peer := Peer{SID: sid, Privileged: sid == "S-1-5-18"}
	for _, group := range groups {
		if group.attributes&windows.SE_GROUP_ENABLED == 0 || group.attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0 {
			continue
		}
		if group.sid == "S-1-5-32-544" {
			peer.Privileged = true
		}
		if fortix != "" && group.sid == fortix {
			peer.Member = true
		}
	}
	return peer
}

// impersonation isolates native token calls for deterministic fatal-revert testing.
type impersonation interface {
	impersonate(windows.Handle) error
	identity(string) (Peer, error)
	revert() error
}

// pipeImpersonation queries the current locked thread rather than the service process token.
type pipeImpersonation struct{}

// procImpersonateNamedPipeClient reuses one lazy binding across control frames.
var procImpersonateNamedPipeClient = windows.NewLazySystemDLL("advapi32.dll").NewProc("ImpersonateNamedPipeClient")

// impersonate binds the calling thread to the last pipe reader's security context.
func (pipeImpersonation) impersonate(handle windows.Handle) error {
	result, _, err := procImpersonateNamedPipeClient.Call(uintptr(handle))
	if result == 0 {
		return err
	}
	return nil
}

// identity copies TokenUser and TokenGroups while the thread remains impersonated.
func (pipeImpersonation) identity(fortix string) (Peer, error) {
	var token windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token); err != nil {
		return Peer{}, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return Peer{}, err
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return Peer{}, err
	}
	copied := make([]tokenGroup, 0, groups.GroupCount)
	for _, group := range groups.AllGroups() {
		copied = append(copied, tokenGroup{group.Sid.String(), group.Attributes})
	}
	return tokenPeer(user.User.Sid.String(), fortix, copied), nil
}

// revert restores the service identity before a thread can rejoin the runtime pool.
func (pipeImpersonation) revert() error { return windows.RevertToSelf() }

// authenticatePipe always reverts after successful impersonation, including query failures.
// A returning test fatal hook panics without unlocking; production terminates the process.
func authenticatePipe(handle windows.Handle, fortix string, api impersonation, fatal func(error)) (Peer, error) {
	runtime.LockOSThread()
	if err := api.impersonate(handle); err != nil {
		runtime.UnlockOSThread()
		return Peer{}, err
	}
	peer, err := api.identity(fortix)
	if revertErr := api.revert(); revertErr != nil {
		fatal(revertErr)
		panic("failed to restore service identity")
	}
	runtime.UnlockOSThread()
	return peer, err
}

// fatalRevert refuses to run any further service code under an unknown thread identity.
func fatalRevert(logger *slog.Logger) func(error) {
	return func(err error) { logger.Error("cannot restore service identity", "error", err); os.Exit(1) }
}

// nativeComputerName supplies the NetBIOS account domain, not the physical DNS hostname.
var nativeComputerName = windows.ComputerName

// nativeLookupSID isolates local account resolution for domain-validation tests.
var nativeLookupSID = windows.LookupSID

// localFortixSID refuses domain or user aliases; absence never prevents administrator access.
func localFortixSID() (string, error) {
	host, err := nativeComputerName()
	if err != nil {
		return "", err
	}
	sid, domain, kind, err := nativeLookupSID("", host+`\fortix`)
	if errors.Is(err, windows.ERROR_NONE_MAPPED) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if kind != windows.SidTypeAlias || !strings.EqualFold(domain, host) {
		return "", errors.New("fortix is not a local group")
	}
	return sid.String(), nil
}

// randomToken returns an unpredictable challenge identifier without retaining random bytes.
func randomToken() (string, error) {
	data := make([]byte, 32)
	defer clear(data)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

// serviceLockAt excludes concurrent recovery workers before any network resource mutation.
func serviceLockAt(dir *helperDirectory) (*os.File, error) {
	f, err := privateFileAt(dir, "helper.lock", os.O_RDWR|os.O_CREATE)
	if err != nil {
		return nil, err
	}
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped); err != nil {
		_ = f.Close()
		return nil, errors.New("helper is already running")
	}
	return f, nil
}
