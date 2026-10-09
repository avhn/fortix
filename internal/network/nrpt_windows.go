package network

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

const (
	nrptRequestLimit = 16 << 10
	nrptOutputLimit  = 64 << 10
)

// nrptRule contains only the values that establish ownership of a local NRPT rule.
type nrptRule struct {
	Name       string   `json:"name"`
	Namespaces []string `json:"namespaces"`
	Servers    []string `json:"servers"`
	Comment    string   `json:"comment"`
}

// nrptRequest keeps operation arguments separate from the immutable PowerShell program.
type nrptRequest struct {
	Operation string   `json:"operation"`
	Rule      nrptRule `json:"rule"`
}

// nrptResponse is the bounded JSON envelope returned even for PowerShell errors.
type nrptResponse struct {
	OK       bool       `json:"ok"`
	Error    string     `json:"error,omitempty"`
	Conflict bool       `json:"conflict,omitempty"`
	Name     string     `json:"name,omitempty"`
	Rules    []nrptRule `json:"rules,omitempty"`
	Policies []nrptRule `json:"policies,omitempty"`
}

// nrptRunner limits the resolver to typed operations rather than arbitrary commands.
type nrptRunner interface {
	Run(context.Context, nrptRequest) (nrptResponse, error)
}

// nrptResolver owns profile-scoped suffix rules without changing adapter DNS settings.
type nrptResolver struct {
	runner nrptRunner
	flush  func() error
	warn   func(error)
	sleep  func(context.Context, time.Duration) error
}

// newNRPTResolver uses only system binaries and logs cache failures without losing ownership.
func newNRPTResolver() *nrptResolver {
	return &nrptResolver{runner: powershellNRPTRunner{}, flush: flushDNSCache, warn: func(err error) {
		log.Printf("DNS resolver cache flush failed: %v", err)
	}}
}

// normalizeNamespaces validates ASCII DNS labels and makes every requested domain a suffix.
func normalizeNamespaces(domains []string) ([]string, error) {
	if len(domains) == 0 || len(domains) > 32 {
		return nil, errors.New("split DNS requires between 1 and 32 namespaces")
	}
	names := make([]string, 0, len(domains))
	for _, domain := range domains {
		name := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(domain, "."), "."))
		if len(name) == 0 || len(name) > 253 {
			return nil, errors.New("invalid split DNS namespace")
		}
		for _, label := range strings.Split(name, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, errors.New("invalid split DNS namespace")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return nil, errors.New("invalid split DNS namespace")
				}
			}
		}
		names = append(names, "."+name)
	}
	slices.Sort(names)
	return slices.Compact(names), nil
}

// normalizeServers rejects hostnames, scopes and unusable endpoints before any mutation.
func normalizeServers(servers []string) ([]string, error) {
	if len(servers) == 0 || len(servers) > 8 {
		return nil, errors.New("split DNS requires between 1 and 8 nameservers")
	}
	result := make([]string, 0, len(servers))
	for _, text := range servers {
		ip, err := netip.ParseAddr(text)
		if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ip == netip.MustParseAddr("255.255.255.255") {
			return nil, errors.New("invalid split DNS nameserver")
		}
		result = append(result, ip.String())
	}
	slices.Sort(result)
	return slices.Compact(result), nil
}

// validNRPTName accepts only the GUID names created by the local DnsClient provider.
func validNRPTName(name string) bool {
	guid, err := windows.GUIDFromString(name)
	return err == nil && guid != (windows.GUID{})
}

// validateResolverIntent binds a canonical ownership marker to its containing journal.
func validateResolverIntent(intent *resolverIntent, installation, profile string) error {
	if intent == nil {
		return nil
	}
	domains, err := normalizeNamespaces(intent.Domains)
	if err != nil || !slices.Equal(domains, intent.Domains) {
		return errors.New("invalid journal DNS namespaces")
	}
	servers, err := normalizeServers(intent.Servers)
	if err != nil || !slices.Equal(servers, intent.Servers) {
		return errors.New("invalid journal DNS servers")
	}
	nonce, err := hex.DecodeString(intent.Nonce)
	if err != nil || len(nonce) != 16 || intent.Nonce != strings.ToLower(intent.Nonce) || intent.Installation != installation || intent.Profile != profile || !validProfileID(profile) {
		return errors.New("invalid journal DNS ownership")
	}
	guid, err := windows.GUIDFromString(installation)
	if err != nil || guid == (windows.GUID{}) || intent.Mode != "split" || intent.Marker != "fortix:"+installation+":"+profile+":"+intent.Nonce || !validState(intent.State) || intent.State == mutationRejected || (intent.Name != "" && !validNRPTName(intent.Name)) || (intent.State == mutationApplied && intent.Name == "") {
		return errors.New("invalid journal DNS rule identity")
	}
	return nil
}

// intentRule builds the complete expected identity without putting any data into script text.
func intentRule(intent *resolverIntent) nrptRule {
	return nrptRule{Name: intent.Name, Namespaces: slices.Clone(intent.Domains), Servers: slices.Clone(intent.Servers), Comment: intent.Marker}
}

// sameNRPTValues compares namespace and address sets while requiring an exact comment marker.
func sameNRPTValues(rule nrptRule, intent *resolverIntent) bool {
	if rule.Comment != intent.Marker || len(rule.Namespaces) != len(intent.Domains) {
		return false
	}
	names := slices.Clone(rule.Namespaces)
	for i := range names {
		names[i] = strings.ToLower(strings.TrimSuffix(names[i], "."))
	}
	slices.Sort(names)
	servers, err := normalizeServers(rule.Servers)
	return err == nil && slices.Equal(names, intent.Domains) && slices.Equal(servers, intent.Servers)
}

// namespacesOverlap treats host, suffix and wildcard policies conservatively at label boundaries.
func namespacesOverlap(a, b string) bool {
	if a == "." || b == "." {
		return true
	}
	a = strings.ToLower(strings.Trim(strings.TrimPrefix(a, "*"), "."))
	b = strings.ToLower(strings.Trim(strings.TrimPrefix(b, "*"), "."))
	return a == b || strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}

// checkNRPTConflicts refuses overlapping local rules and effective policy before Add.
// Only exact marker and value matches are exempt from local conflict checks during a retry.
func checkNRPTConflicts(snapshot nrptResponse, intent *resolverIntent) error {
	for _, rule := range snapshot.Rules {
		if intent.Nonce != "" && sameNRPTValues(rule, intent) {
			continue
		}
		for _, existing := range rule.Namespaces {
			for _, desired := range intent.Domains {
				if namespacesOverlap(existing, desired) {
					return &ConflictError{fmt.Sprintf("DNS namespace %s overlaps an existing DNS rule for %s", desired, existing)}
				}
			}
		}
	}
	for _, policy := range snapshot.Policies {
		for _, existing := range policy.Namespaces {
			for _, desired := range intent.Domains {
				if namespacesOverlap(existing, desired) {
					return &ConflictError{fmt.Sprintf("DNS namespace %s overlaps effective DNS policy for %s", desired, existing)}
				}
			}
		}
	}
	return nil
}

// call rejects script errors before a failed response can authorize ownership changes.
func (r *nrptResolver) call(ctx context.Context, request nrptRequest) (nrptResponse, error) {
	response, err := r.runner.Run(ctx, request)
	if err == nil && !response.OK {
		if response.Conflict {
			err = &ConflictError{"DNS namespace overlaps an existing DNS rule or effective DNS policy"}
		} else {
			err = fmt.Errorf("Windows split DNS failed: %s", response.Error)
		}
	}
	return response, err
}

// flushCache never turns an already completed NRPT change into an ownership failure.
func (r *nrptResolver) flushCache() {
	if err := r.flush(); err != nil && r.warn != nil {
		r.warn(err)
	}
}

// interruptedNRPTName accepts just one exact marked rule without treating overlap as ownership.
func interruptedNRPTName(snapshot nrptResponse, intent *resolverIntent) (string, error) {
	var matches []nrptRule
	for _, rule := range snapshot.Rules {
		if rule.Comment == intent.Marker {
			matches = append(matches, rule)
		}
	}
	if len(matches) > 1 {
		return "", errors.New("DNS rule ownership is ambiguous; journal retained")
	}
	if len(matches) == 0 {
		return "", nil
	}
	if !sameNRPTValues(matches[0], intent) {
		return "", errors.New("interrupted DNS rule values changed; journal retained")
	}
	if !validNRPTName(matches[0].Name) {
		return "", errors.New("DNS rule has an invalid identity; journal retained")
	}
	return matches[0].Name, nil
}

// errNRPTPolicy distinguishes DNS Client propagation lag from a local ownership failure.
var errNRPTPolicy = errors.New("Windows DNS policy from Group Policy overrides local split DNS rules; journal retained")

// waitNRPTPolicy bounds propagation waits by the caller's cancellation or deadline.
func waitNRPTPolicy(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// verifyCreatedNRPT retries only effective-policy lag and rechecks ownership on every snapshot.
func (r *nrptResolver) verifyCreatedNRPT(ctx context.Context, snapshot nrptResponse, intent *resolverIntent) error {
	sleep := r.sleep
	if sleep == nil {
		sleep = waitNRPTPolicy
	}
	for retry := 0; ; retry++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := verifyNRPT(snapshot, intent)
		if !errors.Is(err, errNRPTPolicy) || retry == 5 {
			return err
		}
		if err := sleep(ctx, 200*time.Millisecond); err != nil {
			return err
		}
		snapshot, err = r.call(ctx, nrptRequest{Operation: "snapshot"})
		if err != nil {
			return err
		}
	}
}

// verifyNRPT requires local ownership and effective namespace/server entries before success.
// A local rule alone is insufficient when Group Policy suppresses local DNS configuration.
func verifyNRPT(snapshot nrptResponse, intent *resolverIntent) error {
	if !slices.ContainsFunc(snapshot.Rules, func(rule nrptRule) bool {
		return rule.Name == intent.Name && sameNRPTValues(rule, intent)
	}) {
		return errors.New("DNS rule identity changed or could not be verified; journal retained")
	}
	for _, desired := range intent.Domains {
		found := false
		for _, policy := range snapshot.Policies {
			servers, err := normalizeServers(policy.Servers)
			if err != nil || !slices.Equal(servers, intent.Servers) {
				continue
			}
			for _, namespace := range policy.Namespaces {
				if strings.ToLower(strings.TrimSuffix(namespace, ".")) == desired {
					found = true
				}
			}
		}
		if !found {
			return errNRPTPolicy
		}
	}
	return nil
}

// Apply preflights without writes when persist is nil, otherwise journals nonce before Add.
// A failed acknowledgement remains recoverable by its exact marker and full intent values.
func (r *nrptResolver) Apply(ctx context.Context, intent *resolverIntent, persist func() error) error {
	if intent == nil || intent.Mode != "split" {
		return ctx.Err()
	}
	domains, err := normalizeNamespaces(intent.Domains)
	if err != nil {
		return err
	}
	if persist == nil {
		if len(intent.Servers) != 0 {
			if _, err := normalizeServers(intent.Servers); err != nil {
				return err
			}
		}
		copy := *intent
		copy.Domains = domains
		if intent.Nonce != "" {
			if err := validateResolverIntent(intent, intent.Installation, intent.Profile); err != nil {
				return err
			}
		}
		snapshot, err := r.call(ctx, nrptRequest{Operation: "snapshot"})
		if err != nil {
			return err
		}
		if copy.Name == "" && copy.Nonce != "" {
			copy.Name, err = interruptedNRPTName(snapshot, &copy)
			if err != nil {
				return err
			}
		}
		if copy.Name != "" {
			return verifyNRPT(snapshot, &copy)
		}
		return checkNRPTConflicts(snapshot, &copy)
	}
	if intent.Nonce == "" {
		servers, err := normalizeServers(intent.Servers)
		if err != nil {
			return err
		}
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		intent.Domains, intent.Servers = domains, servers
		intent.Nonce = hex.EncodeToString(nonce[:])
		intent.Marker = "fortix:" + intent.Installation + ":" + intent.Profile + ":" + intent.Nonce
		intent.State = mutationIntent
	}
	if err := validateResolverIntent(intent, intent.Installation, intent.Profile); err != nil {
		return err
	}
	snapshot, err := r.call(ctx, nrptRequest{Operation: "snapshot"})
	if err != nil {
		return err
	}
	if intent.Name != "" {
		return verifyNRPT(snapshot, intent)
	}
	name, err := interruptedNRPTName(snapshot, intent)
	if err != nil {
		return err
	}
	if name != "" {
		intent.Name, intent.State = name, mutationApplied
		if err := persist(); err != nil {
			return err
		}
		defer r.flushCache()
		snapshot, err = r.call(ctx, nrptRequest{Operation: "snapshot"})
		if err != nil {
			return err
		}
		return r.verifyCreatedNRPT(ctx, snapshot, intent)
	}
	if err := checkNRPTConflicts(snapshot, intent); err != nil {
		return err
	}
	if err := persist(); err != nil {
		return err
	}
	result, err := r.call(ctx, nrptRequest{Operation: "add", Rule: intentRule(intent)})
	if err != nil {
		return err
	}
	defer r.flushCache()
	if !validNRPTName(result.Name) {
		return errors.New("added DNS rule has an invalid identity; journal retained")
	}
	intent.Name, intent.State = result.Name, mutationApplied
	if err := persist(); err != nil {
		return err
	}
	snapshot, err = r.call(ctx, nrptRequest{Operation: "snapshot"})
	if err != nil {
		return err
	}
	return r.verifyCreatedNRPT(ctx, snapshot, intent)
}

// Remove reconciles interrupted creation and removes only one fully unchanged owned rule.
// Namespace recovery does not inspect or depend on a tunnel adapter.
func (r *nrptResolver) Remove(ctx context.Context, intent *resolverIntent) error {
	if intent == nil {
		return ctx.Err()
	}
	if err := validateResolverIntent(intent, intent.Installation, intent.Profile); err != nil {
		return err
	}
	snapshot, err := r.call(ctx, nrptRequest{Operation: "snapshot"})
	if err != nil {
		return err
	}
	var matches []nrptRule
	for _, rule := range snapshot.Rules {
		if intent.Name != "" {
			if rule.Name != intent.Name {
				continue
			}
			if !sameNRPTValues(rule, intent) {
				return errors.New("DNS rule identity changed; journal retained")
			}
			matches = append(matches, rule)
		} else if rule.Comment == intent.Marker {
			// A changed marked rule is not evidence that creation never happened.
			if !sameNRPTValues(rule, intent) {
				return errors.New("interrupted DNS rule values changed; journal retained")
			}
			matches = append(matches, rule)
		}
	}
	if len(matches) > 1 {
		return errors.New("DNS rule ownership is ambiguous; journal retained")
	}
	if len(matches) == 1 {
		if !validNRPTName(matches[0].Name) {
			return errors.New("DNS rule has an invalid identity; journal retained")
		}
		if _, err := r.call(ctx, nrptRequest{Operation: "remove", Rule: matches[0]}); err != nil {
			return err
		}
		defer r.flushCache()
		after, err := r.call(ctx, nrptRequest{Operation: "snapshot"})
		if err != nil {
			return err
		}
		for _, rule := range after.Rules {
			if rule.Name == matches[0].Name || intent.Name == "" && rule.Comment == intent.Marker {
				return errors.New("removed DNS rule is still present; journal retained")
			}
		}
	} else {
		r.flushCache()
	}
	return nil
}

// Recover uses the same strict ownership checks for acknowledged and interrupted rules.
func (r *nrptResolver) Recover(ctx context.Context, intent *resolverIntent) error {
	return r.Remove(ctx, intent)
}

// flushDNSCache calls the system DNS API without depending on command lookup or adapter state.
func flushDNSCache() error {
	proc := windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")
	if err := proc.Find(); err != nil {
		return err
	}
	ok, _, err := proc.Call()
	if ok == 0 {
		if err == windows.ERROR_SUCCESS {
			return errors.New("DnsFlushResolverCache failed")
		}
		return err
	}
	return nil
}
