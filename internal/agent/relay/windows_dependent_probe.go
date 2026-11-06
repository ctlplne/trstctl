// SPDX-License-Identifier: BUSL-1.1
package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/windependents"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/servicedependents"
)

func validateDependentProbe(probe connector.WindowsDependentProbe) error {
	if !servicedependents.ValidProbeID(probe.ID) {
		return errors.New("relay: invalid local dependent probe identifier")
	}
	u, e := url.Parse(probe.URL)
	if e != nil || u.Scheme != "http" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Opaque != "" || u.Host == "" || u.Path == "" || !strings.HasPrefix(u.Path, "/") {
		return errors.New("relay: fixed local HTTP functional probe required")
	}
	ip, e := netip.ParseAddr(u.Hostname())
	if e != nil || !ip.IsLoopback() {
		return errors.New("relay: dependent functional probe must use a literal loopback address")
	}
	port, e := strconv.Atoi(u.Port())
	if e != nil || port < 1 || port > 65535 {
		return errors.New("relay: explicit local functional probe port required")
	}
	return nil
}
func validateDependentWriteProfile(grants []connector.WindowsDependentWriteGrant, probes []connector.WindowsDependentProbe) error {
	if len(grants) > 4096 || len(probes) > 4096 {
		return errors.New("relay: local dependent write profile exceeds bound")
	}
	known := map[string]bool{}
	for _, probe := range probes {
		if e := validateDependentProbe(probe); e != nil {
			return e
		}
		if known[probe.ID] {
			return errors.New("relay: duplicate local functional probe identifier")
		}
		known[probe.ID] = true
	}
	seen := map[string]bool{}
	for _, grant := range grants {
		if !windependents.ValidAccountSID(grant.AccountSID) || !known[grant.ProbeID] {
			return errors.New("relay: dependent write grant requires a native SID and local functional probe")
		}
		hash := strings.Repeat("0", 64)
		var e error
		switch grant.Family {
		case "services":
			e = windependents.ValidateServiceSnapshot(windependents.Service{Name: grant.Name, AccountSID: grant.AccountSID, ConfigSHA256: hash})
		case "tasks":
			e = windependents.ValidateTaskSnapshot(windependents.Task{Path: grant.Name, AccountSID: grant.AccountSID, ConfigSHA256: hash, LogonType: 1, ActionCount: 1})
		case "iis":
			e = windependents.ValidatePoolSnapshot(windependents.Pool{Name: grant.Name, AccountSID: grant.AccountSID, ConfigSHA256: hash, EncryptionProvider: "local"})
		default:
			e = errors.New("relay: unknown native dependent family")
		}
		if e != nil {
			return e
		}
		key := grant.AccountSID + "\x00" + grant.Family + "\x00" + strings.ToLower(grant.Name)
		if seen[key] {
			return errors.New("relay: duplicate native dependent write grant")
		}
		seen[key] = true
	}
	return nil
}
func dependentLocalProbe(profile connector.LocalOpsConfig, step servicedependents.RotationStep) (connector.WindowsDependentProbe, error) {
	if e := validateDependentWriteProfile(profile.WindowsDependentWrites, profile.WindowsDependentProbes); e != nil {
		return connector.WindowsDependentProbe{}, e
	}
	allowed := false
	for _, grant := range profile.WindowsDependentWrites {
		if grant.AccountSID == step.AccountSID && grant.Family == step.Ref.Family && strings.EqualFold(grant.Name, step.Ref.Name) && grant.ProbeID == step.ProbeID {
			allowed = true
			break
		}
	}
	if !allowed {
		return connector.WindowsDependentProbe{}, errors.New("relay: exact native dependent write and functional authority absent")
	}
	for _, probe := range profile.WindowsDependentProbes {
		if probe.ID == step.ProbeID {
			return probe, nil
		}
	}
	return connector.WindowsDependentProbe{}, errors.New("relay: local functional probe unavailable")
}
func dependentProbeRequest(ctx context.Context, probe connector.WindowsDependentProbe, step servicedependents.RotationStep, instance string, prepare bool) (servicedependents.FunctionalProof, error) {
	var proof servicedependents.FunctionalProof
	if e := validateDependentProbe(probe); e != nil {
		return proof, e
	}
	if probe.ID != step.ProbeID {
		return proof, errors.New("relay: local functional identifier differs")
	}
	u, e := url.Parse(probe.URL)
	if e != nil {
		return proof, e
	}
	q := u.Query()
	q.Set("challenge", step.Challenge)
	q.Set("phase", "verify")
	if instance != "" {
		q.Set("task_instance_id", instance)
	}
	method := http.MethodGet
	if prepare {
		method = http.MethodPost
		q.Set("phase", "prepare")
	}
	u.RawQuery = q.Encode()
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	request, e := http.NewRequestWithContext(bounded, method, u.String(), nil)
	if e != nil {
		return proof, e
	}
	client := netsec.InsecureLoopbackClient(10 * time.Second)
	defer client.CloseIdleConnections()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		return proof, errors.New("relay: bounded loopback probe transport unavailable")
	}
	transport.DisableCompression = true
	transport.MaxResponseHeaderBytes = 8 << 10
	dial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		return dial(bounded, network, address)
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("relay: functional probe redirects are refused")
	}
	response, e := client.Do(request)
	if e != nil {
		return proof, errors.New("relay: local functional probe transport failed")
	}
	defer func() { _ = response.Body.Close() }()
	if prepare {
		if response.StatusCode != http.StatusNoContent {
			return proof, errors.New("relay: task functional challenge was not prepared")
		}
		return proof, nil
	}
	if response.StatusCode != http.StatusOK || response.ContentLength > 16<<10 {
		return proof, errors.New("relay: local functional probe did not return bounded success evidence")
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 16<<10+1))
	if e != nil || len(raw) > 16<<10 {
		return proof, errors.New("relay: functional evidence exceeds bound")
	}
	if e = servicedependents.DecodeFunctionalProof(raw, &proof); e != nil {
		return proof, e
	}
	if proof.ProbeID != step.ProbeID || proof.Challenge != step.Challenge || proof.AccountSID != step.AccountSID || instance != "" && proof.TaskInstanceID != instance {
		return proof, errors.New("relay: useful work is stale or bound to another native identity")
	}
	return proof, nil
}
func runDependentFunctionalProbe(ctx context.Context, probe connector.WindowsDependentProbe, step servicedependents.RotationStep, instance string) (servicedependents.FunctionalProof, error) {
	return dependentProbeRequest(ctx, probe, step, instance, false)
}
