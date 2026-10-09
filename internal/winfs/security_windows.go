//go:build windows

// Package winfs pins local directories and rejects links before accessing protected files.
package winfs

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileAllAccess is the file object's standard, synchronize and specific full-access mask.
const fileAllAccess = 0x001f01ff

// Policy describes the exact owner and explicit grants of a protected file or directory.
// Administrators is disabled for private user preferences; Extra receives only Rights.
type Policy struct {
	Owner          *windows.SID
	Administrators bool
	Extra          *windows.SID
	Rights         uint32
}

// SystemPolicy grants SYSTEM and Administrators full access, with an optional extra SID.
func SystemPolicy(extra *windows.SID, rights uint32) (Policy, error) {
	owner, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	return Policy{Owner: owner, Administrators: true, Extra: extra, Rights: rights}, err
}

// UserPolicy grants only the current process user and SYSTEM full access.
// A copied SID remains valid after the token query's backing storage is released.
func UserPolicy() (Policy, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return Policy{}, err
	}
	sid, err := user.User.Sid.Copy()
	return Policy{Owner: sid, Extra: sid, Rights: fileAllAccess}, err
}

// Descriptor creates a non-null protected DACL and an explicit owner before creation.
// Directory grants inherit onto children, but each protected child is created explicitly.
func (p Policy) Descriptor(directory bool) (*windows.SECURITY_DESCRIPTOR, error) {
	if p.Owner == nil || !p.Owner.IsValid() || (p.Extra != nil && !p.Extra.IsValid()) || (p.Extra == nil && p.Rights != 0) {
		return nil, errors.New("winfs: invalid security policy")
	}
	flags := ""
	if directory {
		flags = "OICI"
	}
	sddl := "O:" + p.Owner.String() + "D:P(A;" + flags + ";FA;;;SY)"
	if p.Administrators {
		sddl += "(A;" + flags + ";FA;;;BA)"
	}
	if p.Extra != nil && !p.Extra.IsWellKnown(windows.WinLocalSystemSid) {
		sddl += fmt.Sprintf("(A;%s;0x%x;;;%s)", flags, p.Rights, p.Extra.String())
	}
	return windows.SecurityDescriptorFromString(sddl)
}

// Protect applies the exact owner and protected DACL through an already verified handle.
// Callers must request WRITE_OWNER and WRITE_DAC; no path is reopened during protection.
func Protect(handle windows.Handle, p Policy, directory bool) error {
	sd, err := p.Descriptor(directory)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		p.Owner, nil, dacl, nil)
}

// CheckSecurity rejects inherited, null, broad, or foreign-owned security descriptors.
// Matching every ACE avoids treating a single expected grant as evidence of privacy.
func CheckSecurity(handle windows.Handle, p Policy, directory bool) error {
	expected, err := p.Descriptor(directory)
	if err != nil {
		return err
	}
	actual, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := actual.Owner()
	if err != nil || owner == nil || !owner.Equals(p.Owner) {
		return errors.New("winfs: unexpected owner")
	}
	control, _, err := actual.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("winfs: DACL must be protected")
	}
	got, _, err := actual.DACL()
	if err != nil || got == nil {
		return errors.New("winfs: missing DACL")
	}
	want, _, err := expected.DACL()
	if err != nil || want == nil || got.AceCount != want.AceCount {
		return errors.New("winfs: unexpected DACL grants")
	}
	for i := uint32(0); i < uint32(want.AceCount); i++ {
		var a, b *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(got, i, &a); err != nil {
			return err
		}
		if err := windows.GetAce(want, i, &b); err != nil {
			return err
		}
		if a.Header != b.Header || a.Mask != b.Mask || !(*windows.SID)(unsafe.Pointer(&a.SidStart)).Equals((*windows.SID)(unsafe.Pointer(&b.SidStart))) {
			return errors.New("winfs: unexpected DACL entry")
		}
	}
	return nil
}
