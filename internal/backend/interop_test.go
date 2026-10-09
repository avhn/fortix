package backend_test

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/backend"
	"github.com/avhn/fortix/internal/helper"
	"github.com/avhn/fortix/internal/openfortivpn"
	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/secrets"
	"github.com/avhn/fortix/internal/session"
	"github.com/avhn/fortix/internal/tray/model"
)

// interopFixture reads static, synthetic cross-language fixtures without host services.
func interopFixture(t testing.TB, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "interop", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// checkRecords decodes each bounded NDJSON fixture with the production reader and
// verifies production writing preserves every field, including required false values.
// validate checks kind-specific semantics after strict structural decoding.
func checkRecords[T any](t *testing.T, name string, validate func(*testing.T, T)) {
	t.Helper()
	data := interopFixture(t, name)
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Fatal("fixture is empty or lacks final newline")
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	reader := protocol.NewReader(bytes.NewReader(data))
	count := 0
	for scanner.Scan() {
		count++
		line := append([]byte(nil), scanner.Bytes()...)
		t.Run(fmt.Sprintf("%s/%d", name, count), func(t *testing.T) {
			var record T
			if err := reader.Read(&record); err != nil {
				t.Fatal(err)
			}
			validate(t, record)
			var encoded bytes.Buffer
			if err := protocol.Write(&encoded, record); err != nil {
				t.Fatal(err)
			}
			var want, got any
			if err := json.Unmarshal(line, &want); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(encoded.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(want, got) {
				t.Fatalf("wire fields changed: got %s, want %s", encoded.Bytes(), line)
			}
		})
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

// TestProtocolGolden locks request, result, and event shapes for another client language.
// Profile defaults and status payloads are checked against their production types;
// credentials in these records are synthetic and never sent to a socket or keychain.
func TestProtocolGolden(t *testing.T) {
	checkRecords(t, "protocol.requests.ndjson", func(t *testing.T, request protocol.Request) {
		if err := request.Validate(); err != nil {
			t.Fatal(err)
		}
		if request.Op == "profile.put" {
			p, err := profile.Decode(bytes.NewReader(request.ProfileJSON))
			if err != nil {
				t.Fatal(err)
			}
			want := "native"
			if request.ID == "put-external" {
				want = "openfortivpn"
			}
			if p.Backend != want {
				t.Fatalf("backend = %q, want %q", p.Backend, want)
			}
		}
	})
	checkRecords(t, "protocol.results.ndjson", func(t *testing.T, result protocol.Result) {
		if result.Type != "result" || result.ID == "" || result.OK == (result.Error != nil) {
			t.Fatal("invalid result envelope")
		}
		if result.ID == "status-1" || result.ID == "status-empty" {
			data, err := json.Marshal(result.Data)
			if err != nil {
				t.Fatal(err)
			}
			var statuses []helper.Status
			decoder := json.NewDecoder(bytes.NewReader(data))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&statuses); err != nil {
				t.Fatal(err)
			}
			if result.ID == "status-1" && (len(statuses) != 1 || statuses[0].State != session.Connected || statuses[0].Interface != "utun7") {
				t.Fatal("status payload drifted")
			}
		}
	})
	checkRecords(t, "protocol.events.ndjson", func(t *testing.T, event protocol.Event) {
		if event.Profile == "" || event.Attempt == 0 {
			t.Fatal("unbound event fixture")
		}
	})
}

// aggregateCase describes static precedence inputs using snake_case wire-style fields.
// Status is the exact platform-independent presentation status expected by clients.
type aggregateCase struct {
	Name      string             `json:"name"`
	Profiles  []aggregateProfile `json:"profiles"`
	Reachable bool               `json:"reachable"`
	Status    model.Status       `json:"status"`
}

// aggregateProfile carries the flags that distinguish human prompts and dirty cleanup.
type aggregateProfile struct {
	ID              string        `json:"id"`
	State           session.Phase `json:"state"`
	Wanted          bool          `json:"wanted"`
	PendingPassword bool          `json:"pending_password"`
	CleanupPending  bool          `json:"cleanup_pending"`
}

// TestAggregateGolden verifies shared precedence against the existing pure tray model.
// Connected and Partial outrank attention; unreachable snapshots never prove success.
func TestAggregateGolden(t *testing.T) {
	var cases []aggregateCase
	if err := json.Unmarshal(interopFixture(t, "aggregate-status.json"), &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("empty aggregate fixtures")
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			profiles := make([]model.Profile, 0, len(tc.Profiles))
			for _, p := range tc.Profiles {
				profiles = append(profiles, model.Profile{ID: p.ID, State: p.State, Wanted: p.Wanted, PendingPassword: p.PendingPassword, CleanupPending: p.CleanupPending})
			}
			if got := model.Build(profiles, tc.Reachable, model.Preferences{}).Status; got != tc.Status {
				t.Fatalf("status = %s, want %s", got, tc.Status)
			}
		})
	}
}

// keychainVector records exact Go tuple encoding, account hashing, and provider storage.
// Password is synthetic test data; StoredPassword is the native keychain representation.
type keychainVector struct {
	Name           string `json:"name"`
	ID             string `json:"id"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Username       string `json:"username"`
	TupleJSON      string `json:"tuple_json"`
	Service        string `json:"service"`
	Account        string `json:"account"`
	Password       string `json:"password"`
	StoredPassword string `json:"stored_password"`
}

// TestKeychainGolden checks Go JSON escaping and account identity through secrets.Key.
// It also locks the provider's base64 prefix, including Unicode and empty passwords,
// without invoking the OS keychain or reading any real credentials.
func TestKeychainGolden(t *testing.T) {
	var vectors []keychainVector
	if err := json.Unmarshal(interopFixture(t, "keychain.json"), &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("empty keychain fixtures")
	}
	for _, vector := range vectors {
		t.Run(vector.Name, func(t *testing.T) {
			p := profile.Profile{ID: vector.ID, Gateway: profile.Gateway{Host: vector.Host, Port: vector.Port}, Username: vector.Username}
			tuple, err := json.Marshal([]any{vector.Host, vector.Port, vector.Username})
			if err != nil {
				t.Fatal(err)
			}
			if string(tuple) != vector.TupleJSON {
				t.Fatalf("tuple JSON = %s, want %s", tuple, vector.TupleJSON)
			}
			account := fmt.Sprintf("%s:%x:password", vector.ID, sha256.Sum256(tuple))
			if vector.Service != "fortix" || account != vector.Account || secrets.Key(&p)+":password" != vector.Account {
				t.Fatalf("account = %s, want %s", account, vector.Account)
			}
			stored := "go-keyring-base64:" + base64.StdEncoding.EncodeToString([]byte(vector.Password))
			if stored != vector.StoredPassword {
				t.Fatal("provider representation drifted")
			}
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(vector.StoredPassword, "go-keyring-base64:"))
			if err != nil || string(decoded) != vector.Password {
				t.Fatal("native keychain representation does not round trip")
			}
		})
	}
}

// TestExternalAliases proves existing parser and pinentry values retain shared identity.
// Type aliases preserve source compatibility and do not introduce conversion boundaries.
func TestExternalAliases(t *testing.T) {
	for _, pair := range [][2]any{
		{openfortivpn.ConnectedToGateway{}, backend.ConnectedToGateway{}},
		{openfortivpn.Authenticated{}, backend.Authenticated{}},
		{openfortivpn.AuthFailed{}, backend.AuthFailed{}},
		{openfortivpn.TunnelModeDenied{}, backend.TunnelModeDenied{}},
		{openfortivpn.VPNAllocated{}, backend.VPNAllocated{}},
		{openfortivpn.GotAddresses{}, backend.GotAddresses{}},
		{openfortivpn.NegotiationComplete{}, backend.NegotiationComplete{}},
		{openfortivpn.InterfaceUp{}, backend.InterfaceUp{}},
		{openfortivpn.TunnelUp{}, backend.TunnelUp{}},
		{openfortivpn.CertRejected{}, backend.CertificateRejected{}},
		{openfortivpn.RouteRejected{}, backend.RouteRejected{}},
		{openfortivpn.PPPFailure{}, backend.PPPFailure{}},
		{openfortivpn.LoggedOut{}, backend.LoggedOut{}},
		{openfortivpn.Teardown{}, backend.Teardown{}},
		{openfortivpn.Unknown{}, backend.Unknown{}},
		{openfortivpn.Request{}, backend.Request{}},
		{openfortivpn.Password, backend.Password},
	} {
		if reflect.TypeOf(pair[0]) != reflect.TypeOf(pair[1]) {
			t.Fatalf("distinct types: %T and %T", pair[0], pair[1])
		}
	}
}
