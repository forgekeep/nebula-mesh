package meshimport

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/slackhq/nebula/cert"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

const defaultNearExpiryWindow = 30 * 24 * time.Hour

type parsedHost struct {
	proposal HostProposal
	config   ConfigSnapshot
}

func Reconcile(input ReconcileInput) Report {
	reconciler := &reconcileState{
		input:          input,
		addressOwners:  make(map[string][]string),
		addressHosts:   make(map[string]int),
		endpoints:      make(map[string]map[string]struct{}),
		endpointOwners: make(map[string]map[string]struct{}),
		proposal:       Proposal{Hosts: make([]HostProposal, 0), Blocklist: make([]string, 0)},
	}
	if reconciler.input.Now.IsZero() {
		reconciler.input.Now = time.Now()
	}
	if reconciler.input.NearExpiryWindow <= 0 {
		reconciler.input.NearExpiryWindow = defaultNearExpiryWindow
	}
	reconciler.parseNetworkCIDRs()
	reconciler.parseCA()
	reconciler.parseSnapshots()
	reconciler.sortParsedHosts()
	reconciler.reconcileEndpoints()
	reconciler.reconcileTopology()
	reconciler.reconcileFirewall()
	reconciler.reconcileBlocklist()
	reconciler.finish()
	return Report{Blockers: reconciler.blockers, Warnings: reconciler.warnings, Proposal: reconciler.proposal}
}

type reconcileState struct {
	input          ReconcileInput
	networks       []netip.Prefix
	caPool         *cert.CAPool
	hosts          []parsedHost
	addressOwners  map[string][]string
	addressHosts   map[string]int
	endpoints      map[string]map[string]struct{}
	endpointOwners map[string]map[string]struct{}
	blockers       []Issue
	warnings       []Issue
	proposal       Proposal
}

func (r *reconcileState) parseNetworkCIDRs() {
	for i, raw := range r.input.NetworkCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			r.block(IssueInvalidNetworkCIDR, "", "", fmt.Sprintf("network_cidrs[%d]", i), err.Error())
			continue
		}
		r.networks = append(r.networks, prefix.Masked())
	}
}

func (r *reconcileState) parseCA() {
	caCertificate, remainder, err := cert.UnmarshalCertificateFromPEM([]byte(r.input.CACertificatePEM))
	if err != nil || strings.TrimSpace(string(remainder)) != "" || !caCertificate.IsCA() {
		message := "imported CA certificate is invalid"
		if err != nil {
			message = err.Error()
		}
		r.block(IssueInvalidCA, "", "", "ca_certificate", message)
		return
	}
	fingerprint, err := caCertificate.Fingerprint()
	if err != nil {
		r.block(IssueInvalidCA, "", "", "ca_certificate", err.Error())
		return
	}
	if !strings.EqualFold(fingerprint, strings.TrimSpace(r.input.CAFingerprint)) {
		r.block(IssueCAFingerprintMismatch, "", "", "ca_fingerprint", "imported CA fingerprint does not match the certificate")
	}
	caExpired := !r.input.Now.Before(caCertificate.NotAfter())
	switch {
	case caExpired:
		r.block(IssueCACertificateExpired, "", caCertificate.Name(), "ca_certificate", "imported CA certificate is expired")
	case caCertificate.NotAfter().Sub(r.input.Now) <= r.input.NearExpiryWindow:
		r.warn(IssueCACertificateNearExpiry, "", caCertificate.Name(), "ca_certificate", "imported CA certificate is near expiry")
	}
	r.caPool = cert.NewCAPool()
	if err := r.caPool.AddCA(caCertificate); err != nil {
		r.block(IssueInvalidCA, "", caCertificate.Name(), "ca_certificate", err.Error())
		r.caPool = nil
	}
}

func (r *reconcileState) parseSnapshots() {
	for _, snapshot := range r.input.Snapshots {
		if err := ValidateSnapshot(snapshot, r.input.ValidationLimits); err != nil {
			r.block(IssueInvalidSnapshot, snapshot.ID, "", "snapshot", err.Error())
			continue
		}
		r.checkRoots(snapshot)
		r.checkUnsupportedKeys(snapshot)
		if r.parseSnapshotCertificate(snapshot) {
			r.collectEndpoints(snapshot)
		}
	}
}

func (r *reconcileState) parseSnapshotCertificate(snapshot Snapshot) bool {
	hostCertificate, remainder, err := cert.UnmarshalCertificateFromPEM([]byte(snapshot.CertificatePEM))
	if err != nil || strings.TrimSpace(string(remainder)) != "" || hostCertificate.IsCA() {
		message := "host certificate is invalid"
		if err != nil {
			message = err.Error()
		}
		r.block(IssueInvalidHostCertificate, snapshot.ID, "", "certificate", message)
		return false
	}
	fingerprint, err := hostCertificate.Fingerprint()
	if err != nil {
		r.block(IssueInvalidHostCertificate, snapshot.ID, hostCertificate.Name(), "certificate", err.Error())
		return false
	}
	switch {
	case r.input.Now.Before(hostCertificate.NotBefore()):
		r.block(IssueHostCertificateNotYetValid, snapshot.ID, hostCertificate.Name(), "certificate", "host certificate is not yet valid")
	case !r.input.Now.Before(hostCertificate.NotAfter()):
		r.block(IssueHostCertificateExpired, snapshot.ID, hostCertificate.Name(), "certificate", "host certificate is expired")
	case hostCertificate.NotAfter().Sub(r.input.Now) <= r.input.NearExpiryWindow:
		r.warn(IssueHostCertificateNearExpiry, snapshot.ID, hostCertificate.Name(), "certificate", "host certificate is near expiry")
	}
	if r.caPool == nil {
		return false
	}
	verifyAt := r.input.Now
	if verifyAt.Before(hostCertificate.NotBefore()) || !verifyAt.Before(hostCertificate.NotAfter()) {
		verifyAt = hostCertificate.NotBefore().Add(time.Nanosecond)
	}
	if _, err := r.caPool.VerifyCertificate(verifyAt, hostCertificate); err != nil {
		r.block(IssueInvalidHostCertificate, snapshot.ID, hostCertificate.Name(), "certificate", err.Error())
		return false
	}
	if snapshot.Config.ReportedName != "" && snapshot.Config.ReportedName != hostCertificate.Name() {
		r.warn(IssueConfigNameMismatch, snapshot.ID, hostCertificate.Name(), "config.reported_name", "config-reported name differs from certificate identity and was ignored")
	}

	groups := append([]string(nil), hostCertificate.Groups()...)
	sort.Strings(groups)
	host := models.Host{
		ID: snapshot.HostID, NetworkID: r.input.NetworkID, CAID: r.input.CAID,
		Name: hostCertificate.Name(), Groups: groups, Role: models.HostRoleHost,
		ListenPort: snapshot.Config.ListenPort, Status: models.HostStatusImporting,
		CertFingerprint: fingerprint, Kind: models.HostKindAgent,
	}
	host.CertExpiresAt = timePointer(hostCertificate.NotAfter())
	host.Advanced = advancedFromConfig(snapshot.Config)
	if err := models.ValidateHostAdvanced(host.Advanced); err != nil {
		r.block(IssueInvalidAdvanced, snapshot.ID, host.Name, "config", err.Error())
	}
	for _, network := range hostCertificate.Networks() {
		address := network.Addr().Unmap()
		normalized := address.String()
		host.NebulaIPs = append(host.NebulaIPs, normalized)
		if !r.addressWithinNetwork(network) {
			r.block(IssueAddressOutsideNetwork, snapshot.ID, host.Name, "certificate.networks", fmt.Sprintf("certificate prefix %s is outside the target Network CIDRs", network))
		}
		r.addressOwners[normalized] = append(r.addressOwners[normalized], snapshot.ID)
	}
	sort.Strings(host.NebulaIPs)
	if err := models.ValidateHostAddresses(host.NebulaIPs); err != nil {
		r.block(IssueInvalidHostAddresses, snapshot.ID, host.Name, "certificate.networks", err.Error())
	}
	r.hosts = append(r.hosts, parsedHost{
		proposal: HostProposal{SnapshotID: snapshot.ID, Profile: snapshot.Profile, Host: host},
		config:   snapshot.Config,
	})
	return true
}

func (r *reconcileState) sortParsedHosts() {
	sort.Slice(r.hosts, func(i, j int) bool {
		if r.hosts[i].proposal.Host.ID == r.hosts[j].proposal.Host.ID {
			return r.hosts[i].proposal.SnapshotID < r.hosts[j].proposal.SnapshotID
		}
		return r.hosts[i].proposal.Host.ID < r.hosts[j].proposal.Host.ID
	})
	clear(r.addressHosts)
	for index := range r.hosts {
		for _, address := range r.hosts[index].proposal.Host.NebulaIPs {
			if _, exists := r.addressHosts[address]; !exists {
				r.addressHosts[address] = index
			}
		}
	}
}

func (r *reconcileState) addressWithinNetwork(hostPrefix netip.Prefix) bool {
	address := hostPrefix.Addr().Unmap()
	for _, network := range r.networks {
		candidate := network
		if address.Is4() {
			candidate = netip.PrefixFrom(candidate.Addr().Unmap(), candidate.Bits())
		}
		if candidate.Addr().BitLen() == address.BitLen() && candidate.Bits() <= hostPrefix.Bits() && candidate.Contains(address) {
			return true
		}
	}
	return false
}

func advancedFromConfig(config ConfigSnapshot) *models.HostAdvanced {
	advanced := &models.HostAdvanced{
		Punchy: config.Punchy, ListenHost: config.ListenHost, MTU: config.MTU, TunDevice: config.TunDevice,
	}
	for _, route := range config.UnsafeRoutes {
		advanced.UnsafeRoutes = append(advanced.UnsafeRoutes, models.UnsafeRoute{Route: route.Route, Via: route.Via})
	}
	sort.Slice(advanced.UnsafeRoutes, func(i, j int) bool {
		if advanced.UnsafeRoutes[i].Route == advanced.UnsafeRoutes[j].Route {
			return advanced.UnsafeRoutes[i].Via < advanced.UnsafeRoutes[j].Via
		}
		return advanced.UnsafeRoutes[i].Route < advanced.UnsafeRoutes[j].Route
	})
	if advanced.Punchy == nil && advanced.ListenHost == "" && advanced.MTU == 0 && advanced.TunDevice == "" && len(advanced.UnsafeRoutes) == 0 {
		return nil
	}
	return advanced
}

func (r *reconcileState) collectEndpoints(snapshot Snapshot) {
	for rawAddress, rawEndpoints := range snapshot.Config.StaticHostMap {
		address, err := netip.ParseAddr(strings.TrimSpace(rawAddress))
		if err != nil {
			r.block(IssueInvalidEndpoint, snapshot.ID, "", "config.static_host_map", fmt.Sprintf("invalid overlay address %q", rawAddress))
			continue
		}
		normalizedAddress := address.Unmap().String()
		if r.endpoints[normalizedAddress] == nil {
			r.endpoints[normalizedAddress] = make(map[string]struct{})
		}
		for _, rawEndpoint := range rawEndpoints {
			endpoint, err := normalizeEndpoint(rawEndpoint)
			if err != nil {
				r.block(IssueInvalidEndpoint, snapshot.ID, "", "config.static_host_map", err.Error())
				continue
			}
			r.endpoints[normalizedAddress][endpoint] = struct{}{}
			if r.endpointOwners[endpoint] == nil {
				r.endpointOwners[endpoint] = make(map[string]struct{})
			}
			r.endpointOwners[endpoint][normalizedAddress] = struct{}{}
		}
	}
}

func normalizeEndpoint(raw string) (string, error) {
	host, portRaw, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid static endpoint %q", raw)
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return "", fmt.Errorf("static endpoint %q must use an IP address", raw)
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("static endpoint %q has an invalid port", raw)
	}
	return net.JoinHostPort(address.Unmap().String(), strconv.Itoa(port)), nil
}

func (r *reconcileState) reconcileEndpoints() {
	for address, owners := range r.addressOwners {
		if len(owners) > 1 {
			sort.Strings(owners)
			r.block(IssueDuplicateOverlayAddress, strings.Join(owners, ","), "", "certificate.networks", fmt.Sprintf("overlay address %s appears in multiple certificates", address))
		}
	}
	for address, endpoints := range r.endpoints {
		if _, exists := r.addressHosts[address]; !exists {
			r.block(IssueUnknownStaticHost, "", "", "config.static_host_map", fmt.Sprintf("static endpoint refers to overlay address %s which is absent from imported certificates", address))
		}
		if len(endpoints) > 1 {
			r.block(IssueEndpointConflict, "", "", "config.static_host_map", fmt.Sprintf("overlay address %s has conflicting public endpoints: %s", address, strings.Join(sortedSet(endpoints), ", ")))
		}
	}
	for endpoint, addresses := range r.endpointOwners {
		if len(addresses) > 1 {
			r.block(IssueEndpointConflict, "", "", "config.static_host_map", fmt.Sprintf("public endpoint %s is assigned to multiple overlay addresses: %s", endpoint, strings.Join(sortedSet(addresses), ", ")))
		}
	}
}

func (r *reconcileState) reconcileTopology() {
	for i := range r.hosts {
		host := &r.hosts[i]
		switch {
		case host.config.AmLighthouse && host.config.AmRelay:
			host.proposal.Host.Role = models.HostRoleLighthouseRelay
		case host.config.AmLighthouse:
			host.proposal.Host.Role = models.HostRoleLighthouse
		case host.config.AmRelay:
			host.proposal.Host.Role = models.HostRoleRelay
		}
		host.proposal.Host.IsLighthouse = host.proposal.Host.Role.Lighthouse()
		host.proposal.Host.IsRelay = host.proposal.Host.Role.Relay()
		if host.config.AmLighthouse || host.config.AmRelay {
			r.applyRoleEndpoint(host)
		}
		for _, raw := range host.config.LighthouseHosts {
			r.checkTopologyReference(host, raw, true)
		}
		for _, raw := range host.config.Relays {
			r.checkTopologyReference(host, raw, false)
		}
	}
}

func (r *reconcileState) applyRoleEndpoint(host *parsedHost) {
	set := make(map[string]struct{})
	for _, address := range host.proposal.Host.NebulaIPs {
		for endpoint := range r.endpoints[address] {
			set[endpoint] = struct{}{}
		}
	}
	if len(set) == 0 {
		r.block(IssueMissingRoleEndpoint, host.proposal.SnapshotID, host.proposal.Host.Name, "config.static_host_map", "lighthouse or relay has no resolvable static endpoint")
		return
	}
	if len(set) > 1 {
		r.block(IssueEndpointConflict, host.proposal.SnapshotID, host.proposal.Host.Name, "config.static_host_map", "lighthouse or relay addresses resolve to different endpoints")
		return
	}
	endpoint := sortedSet(set)[0]
	publicIP, portRaw, _ := net.SplitHostPort(endpoint)
	port, _ := strconv.Atoi(portRaw)
	host.proposal.Host.PublicIP = publicIP
	host.proposal.Host.ListenPort = port
}

func (r *reconcileState) checkTopologyReference(source *parsedHost, raw string, lighthouse bool) {
	address, err := netip.ParseAddr(strings.TrimSpace(raw))
	code := IssueUnresolvedRelay
	field := "config.relays"
	role := "relay"
	if lighthouse {
		code = IssueUnresolvedLighthouse
		field = "config.lighthouse_hosts"
		role = "lighthouse"
	}
	if err != nil {
		r.block(code, source.proposal.SnapshotID, source.proposal.Host.Name, field, fmt.Sprintf("invalid %s overlay address %q", role, raw))
		return
	}
	index, ok := r.addressHosts[address.Unmap().String()]
	if !ok || (lighthouse && !r.hosts[index].config.AmLighthouse) || (!lighthouse && !r.hosts[index].config.AmRelay) {
		r.block(code, source.proposal.SnapshotID, source.proposal.Host.Name, field, fmt.Sprintf("%s reference %s does not resolve to an imported %s", role, raw, role))
	}
}

func (r *reconcileState) reconcileFirewall() {
	var baseline string
	baselineSet := false
	for i := range r.hosts {
		policy, err := normalizeFirewall(r.hosts[i].config.Firewall)
		if err != nil {
			r.block(IssueInvalidFirewall, r.hosts[i].proposal.SnapshotID, r.hosts[i].proposal.Host.Name, "config.firewall", err.Error())
			continue
		}
		canonical := firewallKey(policy)
		if !baselineSet {
			baseline = canonical
			baselineSet = true
			r.proposal.Firewall = policy
			continue
		}
		if canonical != baseline {
			r.block(IssueDivergentFirewall, r.hosts[i].proposal.SnapshotID, r.hosts[i].proposal.Host.Name, "config.firewall", "firewall policy differs from other imported hosts")
		}
	}
}

func normalizeFirewall(policy FirewallPolicy) (FirewallPolicy, error) {
	out := FirewallPolicy{
		Inbound:  append([]FirewallRule(nil), policy.Inbound...),
		Outbound: append([]FirewallRule(nil), policy.Outbound...),
	}
	for _, direction := range []struct {
		name  string
		rules []FirewallRule
	}{{"inbound", out.Inbound}, {"outbound", out.Outbound}} {
		for i := range direction.rules {
			// Trim into the stored rule, not just for the checks below. The
			// renderer re-validates these values and does not trim, so a rule
			// that is only valid once trimmed would pass the import and then
			// drop the whole network policy to the baseline at render time.
			// Trimming here also keeps whitespace from reading as a policy
			// difference in the divergence comparison.
			rule := &direction.rules[i]
			rule.Port = strings.TrimSpace(rule.Port)
			rule.Proto = strings.TrimSpace(rule.Proto)
			rule.Group = strings.TrimSpace(rule.Group)
			rule.Cidr = strings.TrimSpace(rule.Cidr)
			rule.LocalCidr = strings.TrimSpace(rule.LocalCidr)

			if rule.Port == "" || rule.Proto == "" {
				return FirewallPolicy{}, fmt.Errorf("%s rule %d requires port and proto", direction.name, i)
			}
			// An imported policy is held to the same selector and prefix rules
			// as one an operator writes through the API: exactly one peer
			// selector, and cidr / local_cidr either a prefix or "any".
			if err := models.ValidateFirewallSelectors(rule.Group, rule.Cidr); err != nil {
				return FirewallPolicy{}, fmt.Errorf("%s rule %d: %w", direction.name, i, err)
			}
			if err := models.ValidateFirewallCIDR("local_cidr", rule.LocalCidr); err != nil {
				return FirewallPolicy{}, fmt.Errorf("%s rule %d: %w", direction.name, i, err)
			}
		}
	}
	sortFirewallRules(out.Inbound)
	sortFirewallRules(out.Outbound)
	return out, nil
}

func sortFirewallRules(rules []FirewallRule) {
	sort.Slice(rules, func(i, j int) bool {
		return firewallRuleKey(rules[i]) < firewallRuleKey(rules[j])
	})
}

// firewallRuleKey renders every field of a rule, so that two policies
// differing only in cidr or local_cidr sort apart and compare unequal — the
// divergence check would otherwise treat them as the same policy and apply one
// host's rules to every imported host.
func firewallRuleKey(rule FirewallRule) string {
	return rule.Port + "\x00" + rule.Proto + "\x00" + rule.Group + "\x00" + rule.Cidr + "\x00" + rule.LocalCidr
}

func firewallKey(policy FirewallPolicy) string {
	var builder strings.Builder
	for _, rule := range policy.Inbound {
		fmt.Fprintf(&builder, "i:%s;", firewallRuleKey(rule))
	}
	for _, rule := range policy.Outbound {
		fmt.Fprintf(&builder, "o:%s;", firewallRuleKey(rule))
	}
	return builder.String()
}

func (r *reconcileState) reconcileBlocklist() {
	var baseline string
	for i := range r.hosts {
		blocklist, err := normalizeBlocklist(r.hosts[i].config.Blocklist)
		if err != nil {
			r.block(IssueInvalidBlocklist, r.hosts[i].proposal.SnapshotID, r.hosts[i].proposal.Host.Name, "config.blocklist", err.Error())
		}
		canonical := strings.Join(blocklist, ",")
		if i == 0 {
			baseline = canonical
			r.proposal.Blocklist = blocklist
			continue
		}
		if canonical != baseline {
			r.block(IssueDivergentBlocklist, r.hosts[i].proposal.SnapshotID, r.hosts[i].proposal.Host.Name, "config.blocklist", "blocklist differs from other imported hosts")
		}
	}
	revoked := make(map[string]struct{}, len(r.proposal.Blocklist))
	for _, fingerprint := range r.proposal.Blocklist {
		revoked[fingerprint] = struct{}{}
	}
	for i := range r.hosts {
		fingerprint := strings.ToLower(strings.TrimSpace(r.hosts[i].proposal.Host.CertFingerprint))
		if _, blocked := revoked[fingerprint]; blocked {
			r.hosts[i].proposal.Host.Status = models.HostStatusBlocked
		}
	}
}

func normalizeBlocklist(values []string) ([]string, error) {
	set := make(map[string]struct{}, len(values))
	var invalid []string
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		decoded, err := hex.DecodeString(normalized)
		if err != nil || len(decoded) != 32 {
			invalid = append(invalid, value)
			continue
		}
		set[normalized] = struct{}{}
	}
	out := sortedSet(set)
	if len(invalid) > 0 {
		sort.Strings(invalid)
		return out, fmt.Errorf("invalid certificate fingerprints: %s", strings.Join(invalid, ", "))
	}
	return out, nil
}

func (r *reconcileState) checkRoots(snapshot Snapshot) {
	for _, root := range snapshot.Config.CARootFingerprints {
		if !strings.EqualFold(strings.TrimSpace(root), r.input.CAFingerprint) {
			r.block(IssueExtraCARoot, snapshot.ID, "", "config.ca_roots", fmt.Sprintf("CA root %q differs from the imported CA", root))
		}
	}
	if len(snapshot.Config.CARootFingerprints) > 1 {
		r.block(IssueExtraCARoot, snapshot.ID, "", "config.ca_roots", "config contains more than one CA root")
	}
}

func (r *reconcileState) checkUnsupportedKeys(snapshot Snapshot) {
	keys := append([]string(nil), snapshot.Config.UnsupportedKeys...)
	sort.Strings(keys)
	for _, key := range keys {
		message := fmt.Sprintf("explicit config key %q cannot be represented by nebula-mesh", key)
		if optionalUnsupportedConfigKey(key) {
			r.warn(IssueUnsupportedConfigKey, snapshot.ID, "", key, message)
			continue
		}
		r.block(IssueUnsupportedConfigKey, snapshot.ID, "", key, message)
	}
}

func optionalUnsupportedConfigKey(key string) bool {
	for _, prefix := range []string{"logging.", "stats.", "sshd."} {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

func (r *reconcileState) finish() {
	for i := range r.hosts {
		r.proposal.Hosts = append(r.proposal.Hosts, r.hosts[i].proposal)
	}
	sort.Slice(r.proposal.Hosts, func(i, j int) bool {
		if r.proposal.Hosts[i].Host.ID == r.proposal.Hosts[j].Host.ID {
			return r.proposal.Hosts[i].SnapshotID < r.proposal.Hosts[j].SnapshotID
		}
		return r.proposal.Hosts[i].Host.ID < r.proposal.Hosts[j].Host.ID
	})
	sortIssues(r.blockers)
	sortIssues(r.warnings)
}

func sortIssues(issues []Issue) {
	sort.Slice(issues, func(i, j int) bool {
		left := issues[i].Code + "\x00" + issues[i].SnapshotID + "\x00" + issues[i].HostName + "\x00" + issues[i].Field + "\x00" + issues[i].Message
		right := issues[j].Code + "\x00" + issues[j].SnapshotID + "\x00" + issues[j].HostName + "\x00" + issues[j].Field + "\x00" + issues[j].Message
		return left < right
	})
}

func sortedSet(set map[string]struct{}) []string {
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func (r *reconcileState) block(code, snapshotID, hostName, field, message string) {
	r.blockers = append(r.blockers, Issue{Code: code, SnapshotID: snapshotID, HostName: hostName, Field: field, Message: message})
}

func (r *reconcileState) warn(code, snapshotID, hostName, field, message string) {
	r.warnings = append(r.warnings, Issue{Code: code, SnapshotID: snapshotID, HostName: hostName, Field: field, Message: message})
}

func timePointer(value time.Time) *time.Time { return &value }
