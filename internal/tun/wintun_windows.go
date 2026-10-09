package tun

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Wintun 0.14.1, https://www.wintun.net/builds/wintun-0.14.1.zip.
// Zip SHA-256: 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51.
const (
	wintunZipSHA256   = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
	wintunAMD64SHA256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"
	wintunARM64SHA256 = "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80"
)

// wintunDLL owns one module reference and eagerly resolved, fallible exports.
type wintunDLL struct {
	module windows.Handle
	procs  map[string]uintptr
}

// validateDLLPath rejects search names, alternate streams and remote/device paths.
func validateDLLPath(path string) error {
	if !filepath.IsAbs(path) || len(path) < 3 || path[1] != ':' ||
		strings.HasPrefix(path, `\\`) || strings.Contains(path[2:], ":") ||
		filepath.Clean(path) != path || !strings.EqualFold(filepath.Base(path), "wintun.dll") {
		return errors.New("wintun requires an absolute local DLL path")
	}
	return nil
}

// verifyWintunHash limits reads and rejects all bytes outside the pinned release.
func verifyWintunHash(r io.Reader, arch string) error {
	expected := map[string]string{"amd64": wintunAMD64SHA256, "arm64": wintunARM64SHA256}[arch]
	if expected == "" {
		return errors.New("unsupported wintun architecture")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r, 8*1024*1024+1))
	if err != nil {
		return err
	}
	if n > 8*1024*1024 || fmt.Sprintf("%x", h.Sum(nil)) != expected {
		return errors.New("wintun DLL SHA-256 mismatch")
	}
	return nil
}

// verifyWintunTrust checks the pinned file's Authenticode chain without UI.
// Revocation is offline because VPN setup cannot depend on Internet reachability;
// the exact release hash is checked separately before any code is loaded.
func verifyWintunTrust(path *uint16, handle windows.Handle) error {
	file := windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: path, File: handle}
	data := windows.WinTrustData{Size: uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice: windows.WTD_UI_NONE, RevocationChecks: windows.WTD_REVOKE_NONE,
		UnionChoice: windows.WTD_CHOICE_FILE, StateAction: windows.WTD_STATEACTION_VERIFY,
		ProvFlags:                       windows.WTD_CACHE_ONLY_URL_RETRIEVAL,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&file)}
	err := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	return errors.Join(err, windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data))
}

// loadWintun pins a non-writable, non-deletable file handle through hashing, trust
// verification and restricted loading. The installer must protect its ancestors.
func loadWintun(path string) (*wintunDLL, error) {
	if err := validateDLLPath(path); err != nil {
		return nil, err
	}
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(path16, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return nil, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1 {
		return nil, errors.New("wintun DLL must be a regular single-link file")
	}
	if err := verifyWintunHash(file, runtime.GOARCH); err != nil {
		return nil, err
	}
	if err := verifyWintunTrust(path16, handle); err != nil {
		return nil, fmt.Errorf("wintun signature: %w", err)
	}
	module, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return nil, err
	}
	procs, err := resolveWintunExports(func(name string) (uintptr, error) { return windows.GetProcAddress(module, name) })
	if err != nil {
		return nil, errors.Join(err, windows.FreeLibrary(module))
	}
	return &wintunDLL{module: module, procs: procs}, nil
}

// resolveWintunExports fails before adapter creation if any required export is absent.
func resolveWintunExports(resolve func(string) (uintptr, error)) (map[string]uintptr, error) {
	procs := make(map[string]uintptr)
	for _, name := range []string{"WintunCreateAdapter", "WintunGetAdapterLUID", "WintunStartSession",
		"WintunGetReadWaitEvent", "WintunReceivePacket", "WintunReleaseReceivePacket",
		"WintunAllocateSendPacket", "WintunSendPacket", "WintunEndSession", "WintunCloseAdapter"} {
		address, err := resolve(name)
		if err != nil || address == 0 {
			return nil, fmt.Errorf("resolve %s: %w", name, errors.Join(err, windows.ERROR_PROC_NOT_FOUND))
		}
		procs[name] = address
	}
	return procs, nil
}

// create passes the ledger's random GUID and alias to Wintun, never reusing an adapter.
func (a *wintunDLL) create(name string, guid *windows.GUID) (uintptr, error) {
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	kind, _ := windows.UTF16PtrFromString("Fortix")
	r, _, e := syscall.SyscallN(a.procs["WintunCreateAdapter"], uintptr(unsafe.Pointer(name16)), uintptr(unsafe.Pointer(kind)), uintptr(unsafe.Pointer(guid)))
	if r == 0 {
		return 0, wintunCallError(e)
	}
	return r, nil
}

// identity captures the LUID and current index before the helper configures the link.
func (a *wintunDLL) identity(adapter uintptr) (uint64, uint32, error) {
	var luid uint64
	syscall.SyscallN(a.procs["WintunGetAdapterLUID"], adapter, uintptr(unsafe.Pointer(&luid)))
	proc := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("ConvertInterfaceLuidToIndex")
	if err := proc.Find(); err != nil {
		return 0, 0, err
	}
	var index uint32
	status, _, _ := proc.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&index)))
	if status != 0 {
		return 0, 0, syscall.Errno(status)
	}
	if luid == 0 || index == 0 {
		return 0, 0, errors.New("wintun returned an empty link identity")
	}
	return luid, index, nil
}

// start opens the bounded power-of-two session ring.
func (a *wintunDLL) start(adapter uintptr, capacity uint32) (uintptr, error) {
	r, _, e := syscall.SyscallN(a.procs["WintunStartSession"], adapter, uintptr(capacity))
	if r == 0 {
		return 0, wintunCallError(e)
	}
	return r, nil
}

// readEvent borrows Wintun's event, whose lifetime ends with the session.
func (a *wintunDLL) readEvent(session uintptr) (windows.Handle, error) {
	r, _, e := syscall.SyscallN(a.procs["WintunGetReadWaitEvent"], session)
	if r == 0 {
		return 0, wintunCallError(e)
	}
	return windows.Handle(r), nil
}

// receive borrows kernel-mapped storage until the matching release call.
func (a *wintunDLL) receive(session uintptr) ([]byte, error) {
	var size uint32
	r, _, e := syscall.SyscallN(a.procs["WintunReceivePacket"], session, uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return nil, wintunCallError(e)
	}
	return wintunPacket(r, size), nil
}

// wintunPacket interprets an external allocation, never a Go heap uintptr.
func wintunPacket(address uintptr, size uint32) []byte {
	pointer := *(*unsafe.Pointer)(unsafe.Pointer(&address))
	return unsafe.Slice((*byte)(pointer), int(size))
}

// release relinquishes exactly one successful receive, even for invalid packets.
func (a *wintunDLL) release(session uintptr, packet []byte) {
	syscall.SyscallN(a.procs["WintunReleaseReceivePacket"], session, uintptr(unsafe.Pointer(unsafe.SliceData(packet))))
}

// allocate reserves a send packet or reports ring saturation without blocking.
func (a *wintunDLL) allocate(session uintptr, size uint32) ([]byte, error) {
	r, _, e := syscall.SyscallN(a.procs["WintunAllocateSendPacket"], session, uintptr(size))
	if r == 0 {
		return nil, wintunCallError(e)
	}
	return wintunPacket(r, size), nil
}

// send transfers a filled allocation to Wintun, which owns its storage afterward.
func (a *wintunDLL) send(session uintptr, packet []byte) {
	syscall.SyscallN(a.procs["WintunSendPacket"], session, uintptr(unsafe.Pointer(unsafe.SliceData(packet))))
}

// end releases the ring only after all borrowed packets and I/O have drained.
func (a *wintunDLL) end(session uintptr) { syscall.SyscallN(a.procs["WintunEndSession"], session) }

// closeAdapter closes our adapter handle without touching the installed driver.
func (a *wintunDLL) closeAdapter(adapter uintptr) {
	syscall.SyscallN(a.procs["WintunCloseAdapter"], adapter)
}

// unload drops the module reference after the adapter and session are gone.
func (a *wintunDLL) unload() error { return windows.FreeLibrary(a.module) }

// wintunCallError prevents a null result with a stale zero last-error from succeeding.
func wintunCallError(err syscall.Errno) error {
	if err == 0 {
		return windows.ERROR_GEN_FAILURE
	}
	return err
}
