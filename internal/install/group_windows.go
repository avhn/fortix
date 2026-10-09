package install

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const elevationMessage = "run this from an elevated terminal (Run as administrator)"

// requireElevation checks both TokenElevation and an enabled Administrators group, not a deny-only SID.
func requireElevation() error {
	token := windows.GetCurrentProcessToken()
	groups, err := token.GetTokenGroups()
	if err != nil {
		return errors.New(elevationMessage)
	}
	enabled := false
	for _, group := range groups.AllGroups() {
		if group.Sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) && group.Attributes&windows.SE_GROUP_ENABLED != 0 && group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			enabled = true
		}
	}
	return checkElevation(token.IsElevated(), enabled)
}

// checkElevation isolates the fail-closed authority rule for unprivileged tests.
func checkElevation(elevated, administrator bool) error {
	if !elevated || !administrator {
		return errors.New(elevationMessage)
	}
	return nil
}

// enableRestore enables ownership assignment for SYSTEM-owned state and restores the previous token state.
// Installation is synchronous; the caller pins its thread until the returned cleanup completes.
func enableRestore() (func() error, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES, &token); err != nil {
		return nil, err
	}
	name, _ := windows.UTF16PtrFromString("SeRestorePrivilege")
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
		token.Close()
		return nil, err
	}
	requested := windows.Tokenprivileges{PrivilegeCount: 1, Privileges: [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}}}
	var previous windows.Tokenprivileges
	var size uint32
	if err := adjustPrivileges(token, &requested, uint32(unsafe.Sizeof(previous)), &previous, &size); err != nil {
		token.Close()
		return nil, err
	}
	return func() error { return errors.Join(adjustPrivileges(token, &previous, 0, nil, nil), token.Close()) }, nil
}

// selectedUser resolves an actual user SID; aliases, domain groups and well-known groups are refused.
func selectedUser(name string) (*windows.SID, error) {
	if name == "" {
		linked, err := windows.GetCurrentProcessToken().GetLinkedToken()
		if err == nil {
			user, queryErr := linked.GetTokenUser()
			if queryErr != nil {
				linked.Close()
				return nil, queryErr
			}
			account, domain, kind, lookupErr := user.User.Sid.LookupAccount("")
			linked.Close()
			if lookupErr != nil || kind != windows.SidTypeUser {
				return nil, errors.New("cannot resolve invoking interactive user")
			}
			name = domain + `\` + account
		} else {
			name = os.Getenv("USERNAME")
		}
	}
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("--user is required when no interactive user is available")
	}
	sid, _, kind, err := windows.LookupSID("", name)
	if err != nil {
		return nil, err
	}
	if kind != windows.SidTypeUser || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinLocalServiceSid) || sid.IsWellKnown(windows.WinNetworkServiceSid) {
		return nil, errors.New("--user must identify a user, not a group or service account")
	}
	return sid, nil
}

// localGroupInfo matches LOCALGROUP_INFO_1 for the fixed local alias creation call.
type localGroupInfo struct{ name, comment *uint16 }

// netGroup invokes only fixed NetAPI entry points and returns their NET_API_STATUS result.
func netGroup(operation string, args ...uintptr) error {
	result, _, _ := windows.NewLazySystemDLL("netapi32.dll").NewProc(operation).Call(args...)
	if result != 0 {
		return windows.Errno(result)
	}
	return nil
}

// validateLocalGroup excludes domain and built-in aliases that happen to share the group name.
func validateLocalGroup() error {
	host, err := windows.ComputerName()
	if err != nil {
		return err
	}
	_, domain, kind, err := windows.LookupSID(host, host+`\fortix`)
	if err != nil {
		return err
	}
	if kind != windows.SidTypeAlias || !strings.EqualFold(domain, host) {
		return errors.New("fortix must be an alias in the local account domain")
	}
	return nil
}

// ensureGroup returns whether this run created the local alias; other name collisions fail closed.
func ensureGroup() (bool, error) {
	name, _ := windows.UTF16PtrFromString("fortix")
	comment, _ := windows.UTF16PtrFromString("Fortix helper access")
	info := localGroupInfo{name: name, comment: comment}
	err := netGroup("NetLocalGroupAdd", 0, 1, uintptr(unsafe.Pointer(&info)), 0)
	runtime.KeepAlive(info)
	created := err == nil
	if err != nil && !errors.Is(err, windows.ERROR_ALIAS_EXISTS) && !errors.Is(err, windows.Errno(2223)) {
		return false, err
	}
	if err := validateLocalGroup(); err != nil {
		return created, err
	}
	return created, nil
}

// changeMember adds or removes only a resolved user SID, never an account-name expression.
func changeMember(user *windows.SID, add bool) (bool, error) {
	name, _ := windows.UTF16PtrFromString("fortix")
	member := user
	operation := "NetLocalGroupDelMembers"
	if add {
		operation = "NetLocalGroupAddMembers"
	}
	err := netGroup(operation, 0, uintptr(unsafe.Pointer(name)), 0, uintptr(unsafe.Pointer(&member)), 1)
	runtime.KeepAlive(user)
	runtime.KeepAlive(name)
	if add && errors.Is(err, windows.ERROR_MEMBER_IN_ALIAS) {
		return false, nil
	}
	if !add && errors.Is(err, windows.ERROR_MEMBER_NOT_IN_ALIAS) {
		return false, nil
	}
	return err == nil, err
}

// deleteGroup removes only the verified local alias and is used for explicit purge or rollback.
func deleteGroup() error {
	if err := validateLocalGroup(); err != nil {
		if errors.Is(err, windows.ERROR_NONE_MAPPED) {
			return nil
		}
		return err
	}
	name, _ := windows.UTF16PtrFromString("fortix")
	err := netGroup("NetLocalGroupDel", 0, uintptr(unsafe.Pointer(name)))
	runtime.KeepAlive(name)
	if err != nil {
		return fmt.Errorf("remove fortix group: %w", err)
	}
	return nil
}

// adjustPrivileges checks ERROR_NOT_ALL_ASSIGNED even when the API reports nonzero success.
func adjustPrivileges(token windows.Token, next *windows.Tokenprivileges, size uint32, previous *windows.Tokenprivileges, required *uint32) error {
	proc := windows.NewLazySystemDLL("advapi32.dll").NewProc("AdjustTokenPrivileges")
	ok, _, err := proc.Call(uintptr(token), 0, uintptr(unsafe.Pointer(next)), uintptr(size), uintptr(unsafe.Pointer(previous)), uintptr(unsafe.Pointer(required)))
	runtime.KeepAlive(next)
	runtime.KeepAlive(previous)
	runtime.KeepAlive(required)
	if ok == 0 || errors.Is(err, windows.ERROR_NOT_ALL_ASSIGNED) {
		return err
	}
	return nil
}
