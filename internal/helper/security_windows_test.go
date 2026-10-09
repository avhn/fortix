package helper

import (
	"errors"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/winfs"
)

// TestPipeDescriptor checks exact ACE masks, protected ownership and the absent-group policy.
func TestPipeDescriptor(t *testing.T) {
	for _, group := range []string{"", "S-1-5-21-1-2-3-1001"} {
		sd, err := pipeDescriptor(group)
		if err != nil {
			t.Fatal(err)
		}
		owner, _, err := sd.Owner()
		if err != nil || !owner.IsWellKnown(windows.WinLocalSystemSid) {
			t.Fatal("pipe is not SYSTEM owned")
		}
		control, _, err := sd.Control()
		if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
			t.Fatal("unprotected pipe DACL")
		}
		acl, _, err := sd.DACL()
		if err != nil || acl == nil {
			t.Fatal("missing pipe DACL")
		}
		want := 2
		if group != "" {
			want = 3
		}
		if int(acl.AceCount) != want {
			t.Fatal("unexpected ACE count")
		}
		for index, sid := range append([]string{"S-1-5-18", "S-1-5-32-544"}, group) {
			if sid == "" {
				continue
			}
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(acl, uint32(index), &ace); err != nil {
				t.Fatal(err)
			}
			mask := uint32(windows.GENERIC_ALL)
			if index == 2 {
				mask = pipeMemberRights
			}
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || uint32(ace.Mask) != mask || (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String() != sid {
				t.Fatalf("incorrect ACE %d", index)
			}
			if index == 2 && ace.Mask&(windows.FILE_APPEND_DATA|windows.WRITE_DAC|windows.WRITE_OWNER) != 0 {
				t.Fatal("member can create a pipe instance or change security")
			}
		}
	}
}

// TestPipeFirstInstance refuses squatting without retrying creation under weaker flags.
func TestPipeFirstInstance(t *testing.T) {
	original := nativeCreatePipe
	defer func() { nativeCreatePipe = original }()
	calls := 0
	nativeCreatePipe = func(_ *uint16, flags, mode, maxInstances, outSize, inSize, timeout uint32, _ *windows.SecurityAttributes) (windows.Handle, error) {
		calls++
		if flags&windows.FILE_FLAG_FIRST_PIPE_INSTANCE == 0 || flags&windows.FILE_FLAG_OVERLAPPED == 0 || mode&windows.PIPE_REJECT_REMOTE_CLIENTS == 0 || maxInstances != 16 {
			t.Fatal("unsafe pipe creation flags")
		}
		return windows.InvalidHandle, windows.ERROR_ACCESS_DENIED
	}
	if _, err := listenPipe(""); !errors.Is(err, windows.ERROR_ACCESS_DENIED) || calls != 1 {
		t.Fatalf("squat was not refused: %v, calls %d", err, calls)
	}
}

// TestEnabledTokenGroups distinguishes disabled and deny-only groups from actual grants.
func TestEnabledTokenGroups(t *testing.T) {
	const user = "S-1-5-21-1-2-3-1001"
	const fortix = "S-1-5-21-1-2-3-1002"
	for _, sid := range []string{"S-1-5-32-544", fortix} {
		for _, attrs := range []uint32{0, windows.SE_GROUP_ENABLED, windows.SE_GROUP_USE_FOR_DENY_ONLY, windows.SE_GROUP_ENABLED | windows.SE_GROUP_USE_FOR_DENY_ONLY} {
			peer := tokenPeer(user, fortix, []tokenGroup{{sid, attrs}})
			want := attrs == windows.SE_GROUP_ENABLED
			if (Authorize(peer) == nil) != want {
				t.Fatalf("wrong token policy for %s attributes %x", sid, attrs)
			}
		}
	}
	if Authorize(tokenPeer("S-1-5-18", "", nil)) != nil {
		t.Fatal("SYSTEM refused")
	}
	if Authorize(Peer{UID: 0}) == nil {
		t.Fatal("numeric zero conferred privilege")
	}
	if Authorize(tokenPeer(user, "", []tokenGroup{{fortix, windows.SE_GROUP_ENABLED}})) == nil {
		t.Fatal("missing local group granted membership")
	}
}

// fakeImpersonation records the token lifecycle without impersonating the test runner.
type fakeImpersonation struct {
	calls                               []string
	queryErr, revertErr, impersonateErr error
}

// impersonate records the initial thread security transition.
func (f *fakeImpersonation) impersonate(windows.Handle) error {
	f.calls = append(f.calls, "impersonate")
	return f.impersonateErr
}

// identity injects TokenUser or TokenGroups query failure after impersonation.
func (f *fakeImpersonation) identity(string) (Peer, error) {
	f.calls = append(f.calls, "query")
	return Peer{SID: "S-1-5-18"}, f.queryErr
}

// revert records mandatory restoration, including the fatal failure case.
func (f *fakeImpersonation) revert() error { f.calls = append(f.calls, "revert"); return f.revertErr }

// TestPipeImpersonationFailurePaths requires revert after failed queries and fail-stop on restore failure.
func TestPipeImpersonationFailurePaths(t *testing.T) {
	queryFailure := errors.New("query failed")
	api := &fakeImpersonation{queryErr: queryFailure}
	if _, err := authenticatePipe(0, "", api, func(error) { t.Fatal("unexpected fatal") }); !errors.Is(err, queryFailure) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(api.calls, []string{"impersonate", "query", "revert"}) {
		t.Fatal(api.calls)
	}
	done := make(chan bool, 1)
	go func() {
		failed := false
		defer func() { done <- failed && recover() != nil }()
		api := &fakeImpersonation{revertErr: errors.New("restore failed")}
		_, _ = authenticatePipe(0, "", api, func(error) { failed = true })
	}()
	select {
	case stopped := <-done:
		if !stopped {
			t.Fatal("failed revert returned to service code")
		}
	case <-time.After(time.Second):
		t.Fatal("fatal revert did not stop")
	}
}

// TestSIDRegistry proves canonical stability, bounded exhaustion and no zero for administrators.
func TestSIDRegistry(t *testing.T) {
	registry := sidRegistry{limit: 3}
	admin, err := registry.register("S-1-5-32-544")
	if err != nil || admin == 0 {
		t.Fatal("administrator received SYSTEM identity")
	}
	system, err := registry.register("S-1-5-18")
	if err != nil || system != 0 {
		t.Fatal("SYSTEM identity changed")
	}
	user, err := registry.register("S-1-5-21-1-2-3-1001")
	if err != nil || user == 0 || user == admin {
		t.Fatal("SID handle collision")
	}
	if _, err := registry.register("S-1-5-21-1-2-3-1002"); err == nil {
		t.Fatal("unbounded registry")
	}
	again, err := registry.register("S-1-5-32-544")
	if err != nil || again != admin {
		t.Fatal("live handle was reused")
	}
}

// TestChallengeSIDBinding refuses another SID even when its token carries admin privilege.
func TestChallengeSIDBinding(t *testing.T) {
	registry := sidRegistry{}
	owner, _ := registry.register("S-1-5-21-1-2-3-1001")
	other, _ := registry.register("S-1-5-21-1-2-3-1002")
	system, _ := registry.register("S-1-5-18")
	s := &Server{challenges: map[string]*challengeRoute{"challenge": {uid: owner}}, actors: map[string]*supervisor{"work": {publicOrigin: &connection{uid: owner}}}}
	for _, uid := range []uint32{other, system} {
		result := s.dispatchWindows(&connection{uid: uid, peer: Peer{Privileged: true}}, protocol.Request{ID: "1", Op: "trust", Profile: "work", Digest: "fixture-digest"})
		if result.Error == nil || result.Error.Code != protocol.Unauthorized {
			t.Fatal("another SID reached certificate trust")
		}
		for _, op := range []string{"answer", "cancel"} {
			result := s.dispatchWindows(&connection{uid: uid, peer: Peer{Privileged: true}}, protocol.Request{ID: "1", Op: op, ChallengeID: "challenge", Secret: "fixture-secret"})
			if result.Error == nil || result.Error.Code != protocol.Unauthorized {
				t.Fatal("another SID reached the actor")
			}
		}
	}
}

// TestStorageDescriptor checks that profile, state and log policy never grants group access.
func TestStorageDescriptor(t *testing.T) {
	policy, err := winfs.SystemPolicy(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []bool{false, true} {
		sd, err := policy.Descriptor(directory)
		if err != nil {
			t.Fatal(err)
		}
		owner, _, err := sd.Owner()
		if err != nil || !owner.IsWellKnown(windows.WinLocalSystemSid) {
			t.Fatal("storage owner")
		}
		control, _, _ := sd.Control()
		if control&windows.SE_DACL_PROTECTED == 0 {
			t.Fatal("storage DACL inherited")
		}
		acl, _, _ := sd.DACL()
		if acl == nil || acl.AceCount != 2 {
			t.Fatal("storage grants nonprivileged access")
		}
		for i, sid := range []string{"S-1-5-18", "S-1-5-32-544"} {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(acl, uint32(i), &ace); err != nil {
				t.Fatal(err)
			}
			if ace.Mask != 0x001f01ff || (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String() != sid {
				t.Fatal("storage grant differs from SYSTEM and Administrators full access")
			}
		}
	}
	for _, id := range []string{"con", "prn", "aux", "nul", "com0", "com1", "com9", "lpt0", "lpt1", "lpt9", "../work", "Work", "work."} {
		if ValidID(id) {
			t.Fatalf("reserved profile accepted: %s", id)
		}
	}
	for _, id := range []string{"work", "con-vpn", "com0-vpn", "lpt0-vpn", "com10", "lpt10"} {
		if !ValidID(id) {
			t.Fatalf("ordinary profile rejected: %s", id)
		}
	}
}
