package network

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/avhn/fortix/internal/backend"
	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/tun"
	"github.com/avhn/fortix/internal/winfs"
)

const journalVersion = 1

// mutationState distinguishes unproved intent from acknowledged ownership and rejection.
type mutationState string

const (
	mutationIntent   mutationState = "intent"
	mutationApplied  mutationState = "applied"
	mutationRejected mutationState = "rejected"
)

// Journal preserves the helper's portable fields and adds Windows allocation ownership.
// Pending mutations are deliberately not evidence that an existing resource is ours.
type Journal struct {
	CleanupComplete  bool                  `json:"cleanup_complete,omitempty"`
	Version          int                   `json:"version"`
	Installation     string                `json:"installation"`
	Profile          string                `json:"profile"`
	Attempt          uint64                `json:"attempt"`
	PID              int                   `json:"pid"`
	StartTime        string                `json:"start_time"`
	Interface        string                `json:"interface,omitempty"`
	Backend          string                `json:"backend,omitempty"`
	Link             *backend.LinkIdentity `json:"link,omitempty"`
	Allocation       *tun.Allocation       `json:"allocation,omitempty"`
	Index            uint32                `json:"index,omitempty"`
	LocalIP          string                `json:"local_ip,omitempty"`
	PeerIP           string                `json:"peer_ip,omitempty"`
	MTU              int                   `json:"mtu,omitempty"`
	GatewayIP        string                `json:"gateway_ip,omitempty"`
	GatewayException *JournalGateway       `json:"gateway_exception,omitempty"`
	Routes           []JournalRoute        `json:"routes,omitempty"`
	Address          *JournalAddress       `json:"address,omitempty"`
	Settings         *JournalInterface     `json:"settings,omitempty"`
	ResolverFiles    []JournalResolver     `json:"resolver_files,omitempty"`
	DNSConfigured    bool                  `json:"dns_configured,omitempty"`
	DNSServers       []string              `json:"dns_servers,omitempty"`
	DNSDomains       []string              `json:"dns_domains,omitempty"`
	Resolver         *resolverIntent       `json:"resolver,omitempty"`
}

// JournalRoute records the complete stable row identity, including metric and protocol.
type JournalRoute struct {
	CIDR      string        `json:"cidr"`
	Gateway   string        `json:"gateway,omitempty"`
	Interface string        `json:"interface"`
	LUID      uint64        `json:"luid"`
	Index     uint32        `json:"index"`
	Metric    uint32        `json:"metric"`
	Protocol  uint32        `json:"protocol"`
	State     mutationState `json:"state"`
}

// JournalGateway binds one profile reference to a borrowed or owned physical host row.
type JournalGateway struct {
	Route JournalRoute `json:"route"`
	Index int          `json:"index"`
	Owned bool         `json:"owned"`
	GUID  windows.GUID `json:"guid"`
}

// JournalAddress retains address identity independently from mutable DAD state.
type JournalAddress struct {
	IP                         string `json:"ip"`
	Prefix                     uint8  `json:"prefix"`
	PrefixOrigin, SuffixOrigin uint32
	State                      mutationState `json:"state"`
}

// interfaceValues contains precisely the settings changed by this manager.
type interfaceValues struct {
	MTU, Metric     uint32
	AutomaticMetric uint8
}

// JournalInterface retains prior settings so an unchanged owned modification can be undone.
type JournalInterface struct {
	Before, After interfaceValues
	State         mutationState `json:"state"`
}

// JournalResolver retains source compatibility; Windows never accepts resolver files.
type JournalResolver struct{ Path, Content, Temporary string }

// resolverIntent binds profile-scoped namespaces to a random marker and the returned rule GUID.
type resolverIntent struct {
	Mode             string `json:"mode"`
	Domains, Servers []string
	Name, Marker     string
	Nonce            string        `json:"nonce"`
	Installation     string        `json:"installation"`
	Profile          string        `json:"profile"`
	State            mutationState `json:"state"`
}

// resolverBinding keeps DNS recovery independent of whether the adapter still exists.
// Apply with a nil callback is a no-write preflight; a non-nil callback persists its journal intent.
type resolverBinding interface {
	Apply(context.Context, *resolverIntent, func() error) error
	Remove(context.Context, *resolverIntent) error
	Recover(context.Context, *resolverIntent) error
}

// stateStore isolates protected durable storage from transaction tests.
type stateStore interface {
	write(context.Context, string, []byte) error
	read(string) ([]byte, error)
	remove(string) error
	names() ([]string, error)
}

// protectedState pins the State directory and enforces SYSTEM/Administrators-only DACLs.
type protectedState struct{ path string }

// root creates only missing protected directories and refuses foreign existing security.
func (s protectedState) root() (*winfs.Root, winfs.Policy, error) {
	policy, err := winfs.SystemPolicy(nil, 0)
	if err != nil {
		return nil, policy, err
	}
	root, err := winfs.SecureDirectory(s.path, policy)
	return root, policy, err
}

// write publishes a flushed same-directory stage through the protected filesystem layer.
func (s protectedState) write(ctx context.Context, name string, data []byte) error {
	root, policy, err := s.root()
	if err != nil {
		return err
	}
	defer root.Close()
	return root.AtomicWrite(ctx, name, data, policy)
}

// read bounds each record before strict decoding and normalizes absent-file errors.
func (s protectedState) read(name string) ([]byte, error) {
	root, policy, err := s.root()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.Open(name, policy)
	if winfs.IsNotExist(err) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if len(data) > 1<<20 {
		return nil, errors.New("network journal exceeds limit")
	}
	return data, err
}

// names enumerates only basenames while pinned ancestors prevent directory replacement.
func (s protectedState) names() ([]string, error) {
	root, _, err := s.root()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := os.Open(s.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	names, err := f.Readdirnames(4097)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(names) > 4096 {
		return nil, errors.New("too many state records")
	}
	return names, nil
}

// remove opens a single child relative to the pinned root and deletes that exact handle.
func (s protectedState) remove(name string) error {
	if filepath.Base(name) != name || strings.ContainsAny(name, `\/:`) {
		return errors.New("invalid journal name")
	}
	root, policy, err := s.root()
	if err != nil {
		return err
	}
	defer root.Close()
	object, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return err
	}
	oa := windows.OBJECT_ATTRIBUTES{RootDirectory: root.Handle(), ObjectName: object, Attributes: windows.OBJ_CASE_INSENSITIVE}
	oa.Length = uint32(unsafe.Sizeof(oa))
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, windows.DELETE|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE, &oa, &status, nil, 0,
		windows.FILE_SHARE_READ, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if winfs.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return errors.New("unsafe journal deletion target")
	}
	if err := winfs.CheckSecurity(handle, policy, false); err != nil {
		return err
	}
	remove := byte(1)
	return windows.SetFileInformationByHandle(handle, windows.FileDispositionInfo, &remove, 1)
}

// decodeRecord rejects unknown fields and trailing JSON rather than weakening recovery validation.
func decodeRecord(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing journal data")
	}
	return nil
}

// allocationRecord binds the pre-create Wintun ledger to one installation.
type allocationRecord struct {
	Version      int
	Installation string
	Allocation   tun.Allocation
	Index        uint32
}

// ensureInstallation loads or creates the protected installation UUID before ownership writes.
func (m *Manager) ensureInstallation(ctx context.Context) error {
	if m.installation != "" {
		return nil
	}
	data, err := m.store.read("network-install.json")
	if errors.Is(err, os.ErrNotExist) {
		guid, err := windows.GenerateGUID()
		if err != nil {
			return err
		}
		data, err = json.Marshal(guid.String())
		if err != nil {
			return err
		}
		if err := m.store.write(ctx, "network-install.json", data); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	var value string
	if err := decodeRecord(data, &value); err != nil {
		return err
	}
	guid, err := windows.GUIDFromString(value)
	if err != nil || guid == (windows.GUID{}) {
		return errors.New("invalid network installation identity")
	}
	m.installation = value
	return nil
}

// validAllocation checks the random pre-create identity, not a friendly-name heuristic.
func validAllocation(a tun.Allocation) bool {
	nonce, err := hex.DecodeString(a.Nonce)
	return err == nil && len(nonce) == 16 && a.Nonce == strings.ToLower(a.Nonce) && a.GUID != (windows.GUID{}) && a.Name == "fortix-"+a.Nonce[:16]
}

// allocationName keys records by the random allocation GUID rather than an adapter alias.
func allocationName(a tun.Allocation) string {
	return "network-allocation-" + a.GUID.String() + ".json"
}

// journalName confines profile journal names to validated ASCII identifiers.
func journalName(j Journal) string {
	return fmt.Sprintf("network-attempt-%s-%d.json", j.Profile, j.Attempt)
}

// validProfileID prevents path aliases without depending on helper package internals.
func validProfileID(id string) bool { return profile.ValidID(id) }

// AllocationHook is wired through tun.SetAllocationHook before P6 accepts requests.
// It persists pre-create intent and later LUID/index discovery under the transaction gate.
func (m *Manager) AllocationHook(a tun.Allocation) error {
	ctx := context.Background()
	if err := m.beginTransaction(ctx); err != nil {
		return err
	}
	defer m.endTransaction()
	if !validAllocation(a) {
		return errors.New("invalid Wintun allocation")
	}
	if err := m.ensureInstallation(ctx); err != nil {
		return err
	}
	record := allocationRecord{Version: journalVersion, Installation: m.installation, Allocation: a}
	data, err := m.store.read(allocationName(a))
	if err == nil {
		var prior allocationRecord
		if err := decodeRecord(data, &prior); err != nil {
			return err
		}
		if prior.Version != journalVersion || prior.Installation != m.installation || prior.Allocation.GUID != a.GUID || prior.Allocation.Name != a.Name || prior.Allocation.Nonce != a.Nonce || (prior.Allocation.LUID != 0 && prior.Allocation.LUID != a.LUID) {
			return errors.New("allocation identity changed")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if a.LUID != 0 {
		return errors.New("allocation intent missing")
	}
	if a.LUID != 0 {
		adapters, err := m.api.adapters()
		if err != nil {
			return err
		}
		for _, adapter := range adapters {
			if adapter.row.InterfaceGuid == a.GUID && adapter.row.InterfaceLuid == a.LUID && windows.UTF16ToString(adapter.row.Alias[:]) == a.Name {
				record.Index = adapter.row.InterfaceIndex
			}
		}
		if record.Index == 0 {
			return &InterfaceError{}
		}
	}
	data, err = json.Marshal(record)
	if err != nil {
		return err
	}
	return m.store.write(ctx, allocationName(a), data)
}

// save writes the authoritative Windows journal before notifying the helper's own store.
func (m *Manager) save(ctx context.Context, j *Journal, persist func(Journal) error) error {
	if err := m.validateJournal(*j); err != nil {
		return err
	}
	data, err := json.Marshal(j)
	if err != nil {
		return err
	}
	if err := m.store.write(ctx, journalName(*j), data); err != nil {
		return err
	}
	if persist != nil {
		return persist(*j)
	}
	return nil
}

// validState accepts only known transaction states; zero is never evidence of ownership.
func validState(state mutationState) bool {
	return state == mutationIntent || state == mutationApplied || state == mutationRejected
}

// validateJournal validates every mutation before recovery can change the first resource.
func (m *Manager) validateJournal(j Journal) error {
	if j.Version != journalVersion || j.Installation == "" || j.Installation != m.installation || !validProfileID(j.Profile) || j.Attempt == 0 || j.Backend != "native" || j.PID != 0 || j.StartTime != "" || j.Allocation == nil || !validAllocation(*j.Allocation) || j.Allocation.LUID == 0 || j.Index == 0 || j.Interface != j.Allocation.Name || j.Link == nil || j.Link.Interface != j.Interface || j.Link.Index != int(j.Index) || j.Link.PID != 0 || j.Link.StartTime != "" {
		return errors.New("invalid Windows network journal")
	}
	if len(j.Routes) > maxCarvedRoutes || len(j.ResolverFiles) != 0 || j.DNSConfigured || len(j.DNSServers) != 0 || len(j.DNSDomains) != 0 {
		return errors.New("unsupported Windows journal resources")
	}
	if j.CleanupComplete && (len(j.Routes) != 0 || j.Address != nil || j.Settings != nil || j.GatewayException != nil || j.Resolver != nil) {
		return errors.New("completed cleanup has remaining resources")
	}
	for _, route := range j.Routes {
		if err := validateRoute(route); err != nil {
			return err
		}
		if route.LUID != j.Allocation.LUID || route.Index != j.Index || route.Interface != j.Interface || route.Protocol != windows.MIB_IPPROTO_NETMGMT || !validState(route.State) {
			return errors.New("route allocation mismatch")
		}
	}
	if j.Address != nil {
		if !validIPv4(j.Address.IP) || j.Address.IP != j.LocalIP || j.Address.Prefix != 32 || j.Address.PrefixOrigin != 1 || j.Address.SuffixOrigin != 1 || !validState(j.Address.State) {
			return errors.New("invalid address journal")
		}
	}
	if j.Settings != nil {
		if j.Settings.Before.MTU < 68 || j.Settings.Before.MTU > 65535 || j.Settings.After.MTU != uint32(j.MTU) || j.MTU < 68 || j.MTU > 65535 || j.Settings.Before.AutomaticMetric > 1 || j.Settings.After.AutomaticMetric != 0 || j.Settings.After.Metric != 5 || !validState(j.Settings.State) {
			return errors.New("invalid interface journal")
		}
	}
	// Loopback TLS peers need no physical host lease for split routes.
	// Address and gateway-exception validation still forbid loopback tunnel resources.
	peer, peerErr := netip.ParseAddr(j.GatewayIP)
	loopbackPeer := peerErr == nil && peer.Is4() && peer.IsLoopback() && peer.String() == j.GatewayIP
	if j.GatewayIP != "" && !validIPv4(j.GatewayIP) && !loopbackPeer {
		return errors.New("invalid TLS peer journal")
	}
	if j.GatewayException != nil {
		if err := validateGateway(*j.GatewayException, j.GatewayIP); err != nil {
			return err
		}
	}
	return validateResolverIntent(j.Resolver, j.Installation, j.Profile)
}

// removeAdapter delegates only verified durable GUID ownership to the Wintun remover.
func (ipHelper) removeAdapter(guid windows.GUID) error { return tun.RemoveOrphan(guid) }
