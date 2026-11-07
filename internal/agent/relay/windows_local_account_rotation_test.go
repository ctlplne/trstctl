// SPDX-License-Identifier: BUSL-1.1
package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/agent/reportstate"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/winaccounts"
	"trstctl.com/trstctl/internal/hostaccounts"
)

func localRotationIntent(t *testing.T) hostaccounts.RotationIntent {
	t.Helper()
	i, e := hostaccounts.NewRotationIntent(hostaccounts.RotationIntent{RotationID: "58910000-0000-4000-8000-000000000001", AccountID: "58910000-0000-4000-8000-000000000002", TenantID: "58910000-0000-4000-8000-000000000003", AgentID: "58910000-0000-4000-8000-000000000004", InventoryRunID: "58910000-0000-4000-8000-000000000005", Native: winaccounts.RotationBinding{Machine: winaccounts.Machine{Name: "OWNED", SID: "S-1-5-21-1-2-3", Role: 3}, Account: winaccounts.Account{Name: "Owned Admin", SID: "S-1-5-21-1-2-3-1001", Enabled: true, PasswordRequired: true}}})
	if e != nil {
		t.Fatal(e)
	}
	return i
}
func localRotationProfile(i hostaccounts.RotationIntent) connector.LocalOpsConfig {
	return connector.LocalOpsConfig{WindowsLocalAccountWrites: []hostaccounts.RotationGrant{{TenantID: i.TenantID, AgentID: i.AgentID, MachineSID: i.Native.Machine.SID, AccountSID: i.Native.Account.SID}}}
}

type localRotationNative struct {
	calls   int
	unknown bool
}

func (n *localRotationNative) Rotate(ctx context.Context, b winaccounts.RotationBinding, generation string, old, next []byte, fence winaccounts.RotationFence) (winaccounts.RotationProof, error) {
	n.calls++
	if len(old) == 0 || !crypto.ValidAccountPassword(next, 24) {
		return winaccounts.RotationProof{}, winaccounts.ErrRotationInvalid
	}
	fresh, e := fence.Begin(ctx, b, generation)
	if e != nil || !fresh {
		return winaccounts.RotationProof{}, winaccounts.ErrRotationUncertain
	}
	if n.unknown {
		return winaccounts.RotationProof{}, winaccounts.ErrRotationUncertain
	}
	p := winaccounts.RotationProof{Binding: b, GenerationID: generation, NewAuthenticated: true, OldRefused: true, ObservedAt: time.Now().UTC()}
	if e = fence.Complete(ctx, p); e != nil {
		return winaccounts.RotationProof{}, e
	}
	return p, nil
}

type localRotationChannel struct {
	wireLiveAtReport bool
	materialExpiry   time.Time
	nativeDeadline   time.Time
	Channel
	store                            *reportstate.Store
	native                           *localRotationNative
	tenant, agent                    string
	unsupported, extra, accept       bool
	redemptions, executions, generic int
	wire                             map[string][]byte
	report                           hostaccounts.RotationReport
	raw                              []byte
	kinds                            []string
}

func newLocalRotationChannel(t *testing.T, i hostaccounts.RotationIntent) *localRotationChannel {
	t.Helper()
	s, e := reportstate.Open(t.TempDir(), i.TenantID+"/"+i.AgentID+"/server")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	return &localRotationChannel{store: s, native: &localRotationNative{}, tenant: i.TenantID, agent: i.AgentID, accept: true}
}
func (c *localRotationChannel) ClaimJobs(_ context.Context, kinds []string, _, _ int) ([]Job, error) {
	c.kinds = append([]string(nil), kinds...)
	return nil, nil
}
func (c *localRotationChannel) AuthorizeLocalAccountRotation(_ context.Context, i hostaccounts.RotationIntent) error {
	if c.unsupported {
		return winaccounts.ErrUnsupported
	}
	if i.TenantID != c.tenant || i.AgentID != c.agent {
		return errors.New("foreign certificate authority")
	}
	return nil
}
func (c *localRotationChannel) ReplayLocalAccountRotation(ctx context.Context, job int64, i hostaccounts.RotationIntent) (winaccounts.RotationProof, bool, error) {
	return c.store.ReplayLocalAccountRotation(ctx, job, i.Native, i.RotationID, i.PredecessorGenerationID)
}
func (c *localRotationChannel) ExecuteLocalAccountRotation(ctx context.Context, job int64, i hostaccounts.RotationIntent, old, next []byte) (winaccounts.RotationProof, error) {
	c.executions++
	c.nativeDeadline, _ = ctx.Deadline()
	return c.store.ExecuteLocalAccountRotationOnce(ctx, job, i.Native, i.RotationID, i.PredecessorGenerationID, old, next, c.native)
}
func (c *localRotationChannel) RedeemLocalAccountRotationCredential(ctx context.Context, job int64, attempt int, _ hostaccounts.RotationIntent) (map[string][]byte, time.Time, error) {
	values, e := c.RedeemJobCredential(ctx, job, attempt)
	expires := c.materialExpiry
	if expires.IsZero() {
		expires = time.Now().Add(time.Minute)
	}
	return values, expires, e
}
func (c *localRotationChannel) RedeemJobCredential(context.Context, int64, int) (map[string][]byte, error) {
	c.redemptions++
	old := bytes.Repeat([]byte{'x'}, 32)
	next := bytes.Repeat([]byte{'z'}, 32)
	next[0] = 'A'
	next[1] = '9'
	c.wire = map[string][]byte{hostaccounts.RotationOldCredentialName: old, hostaccounts.RotationNewCredentialName: next}
	if c.extra {
		c.wire["unexpected"] = bytes.Repeat([]byte{'q'}, 32)
	}
	return c.wire, nil
}
func (c *localRotationChannel) ReportLocalAccountRotation(ctx context.Context, job int64, attempt int, i hostaccounts.RotationIntent, r hostaccounts.RotationReport) (bool, error) {
	for _, value := range c.wire {
		for _, b := range value {
			if b != 0 {
				c.wireLiveAtReport = true
			}
		}
	}
	raw, e := hostaccounts.MarshalRotationReport(i, r)
	if e != nil {
		return false, e
	}
	c.report = r
	c.raw = raw
	o := reportstate.Observation{JobID: job, Attempt: attempt, Outcome: "failed", Detail: raw, EvidenceDigest: crypto.SHA256Hex(raw)}
	if r.Status == "succeeded" {
		o.Outcome = "verified"
		o.LocalAccountRotation = r.Proof
	}
	if e = c.store.Put(o); e != nil {
		return false, e
	}
	if c.accept {
		if e = c.store.Acknowledge(o); e != nil {
			return false, e
		}
	}
	return c.accept, nil
}
func (c *localRotationChannel) ReportJobResult(context.Context, int64, int, string, string, string) (bool, error) {
	c.generic++
	return true, nil
}
func rotationJob(t *testing.T, i hostaccounts.RotationIntent) Job {
	t.Helper()
	raw, e := json.Marshal(i)
	if e != nil {
		t.Fatal(e)
	}
	return Job{JobID: 589, Attempt: 1, Kind: KindWindowsLocalAccountRotation, LeaseExpiresUnix: time.Now().Add(time.Minute).Unix(), Payload: raw}
}
func TestLocalAccountRotationTransportUsesExactGrantAndReplaysWithoutRedemptionA268(t *testing.T) {
	i := localRotationIntent(t)
	c := newLocalRotationChannel(t, i)
	job := rotationJob(t, i)
	if runJob(t.Context(), c, nil, connector.LocalOpsConfig{WindowsLocalAccountsInventory: true}, nil, nil, nil, job) || c.redemptions != 0 || c.native.calls != 0 || c.report.Status != "refused" || c.report.Failure != "local_grant_absent" {
		t.Fatal("inventory-only grant authorized native password work")
	}
	c.accept = false
	if !runJob(t.Context(), c, nil, localRotationProfile(i), nil, nil, nil, job) || c.redemptions != 1 || c.native.calls != 1 || c.report.Status != "succeeded" {
		t.Fatal("exact authorized native operation did not return proof")
	}
	first := append([]byte(nil), c.raw...)
	for _, raw := range c.wire {
		for _, b := range raw {
			if b != 0 {
				t.Fatal("wire credential bytes were retained")
			}
		}
	}
	if !runJob(t.Context(), c, nil, localRotationProfile(i), nil, nil, nil, job) || c.redemptions != 1 || c.native.calls != 1 || !bytes.Equal(first, c.raw) {
		t.Fatal("lost native receipt changed facts or redeemed/rotated again")
	}
	c.accept = true
	if !runJob(t.Context(), c, nil, localRotationProfile(i), nil, nil, nil, job) || c.redemptions != 1 {
		t.Fatal("exact receipt acknowledgement repeated native work")
	}
	job.JobID = 3
	job.Attempt = 2
	if !runJob(t.Context(), c, nil, localRotationProfile(i), nil, nil, nil, job) || c.redemptions != 1 || c.native.calls != 1 || !bytes.Equal(first, c.raw) {
		t.Fatal("recreated delivery lost stable generation proof")
	}
}
func TestLocalAccountRotationRefusesForeignLeaseGrantOrUnsupportedBeforeRedemptionA268(t *testing.T) {
	for _, kind := range []string{"tenant", "agent", "sid", "expired", "unsupported", "busy", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			i := localRotationIntent(t)
			c := newLocalRotationChannel(t, i)
			profile := localRotationProfile(i)
			job := rotationJob(t, i)
			switch kind {
			case "tenant":
				c.tenant = i.AccountID
			case "agent":
				c.agent = i.AccountID
			case "sid":
				profile.WindowsLocalAccountWrites[0].AccountSID = "S-1-5-21-1-2-3-1002"
			case "expired":
				job.LeaseExpiresUnix = time.Now().Add(-time.Minute).Unix()
			case "unsupported":
				c.unsupported = true
			case "busy":
				localAccountRotationSlots <- struct{}{}
				defer func() { <-localAccountRotationSlots }()
			case "malformed":
				job.Payload = []byte(`{"password":"forbidden"}`)
			}
			if runJob(t.Context(), c, nil, profile, nil, nil, nil, job) || c.redemptions != 0 || c.native.calls != 0 {
				t.Fatal("unbound/expired native authority reached credentials or effect")
			}
		})
	}
}
func TestLocalAccountRotationUncertainJournalNeverRedeemsOrResetsAgainA268(t *testing.T) {
	i := localRotationIntent(t)
	c := newLocalRotationChannel(t, i)
	c.native.unknown = true
	job := rotationJob(t, i)
	if runJob(t.Context(), c, nil, localRotationProfile(i), nil, nil, nil, job) || c.report.Status != "uncertain" || c.redemptions != 1 || c.native.calls != 1 {
		t.Fatal("unknown native reset became success")
	}
	job.Attempt++
	if runJob(t.Context(), c, nil, localRotationProfile(i), nil, nil, nil, job) || c.report.Status != "uncertain" || c.redemptions != 1 || c.native.calls != 1 {
		t.Fatal("unknown started journal repeated credential redemption or native write")
	}
}
func TestLocalAccountRotationUnexpectedMaterialIsWipedWithoutNativeEffectA268(t *testing.T) {
	i := localRotationIntent(t)
	c := newLocalRotationChannel(t, i)
	c.extra = true
	if runJob(t.Context(), c, nil, localRotationProfile(i), nil, nil, nil, rotationJob(t, i)) || c.native.calls != 0 || c.redemptions != 1 || c.report.Failure != "credential_unavailable" {
		t.Fatal("extra credential expanded native authority")
	}
	for _, raw := range c.wire {
		if !bytes.Equal(raw, make([]byte, len(raw))) {
			t.Fatal("refused wire material was retained")
		}
		secret.Wipe(raw)
	}
}
func TestLocalAccountRotationProfileAndHostClaimAreNarrowA268(t *testing.T) {
	i := localRotationIntent(t)
	profile := HostProfile{WindowsLocalAccountWrites: localRotationProfile(i).WindowsLocalAccountWrites}
	raw, _ := json.Marshal(profile)
	name := filepath.Join(t.TempDir(), "host.json")
	root, e := os.OpenRoot(filepath.Dir(name))
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = root.Close() }()
	if e = root.WriteFile("host.json", raw, 0600); e != nil {
		t.Fatal(e)
	}
	loaded, e := LoadHostProfile(name)
	if e != nil || len(loaded.WindowsLocalAccountWrites) != 1 || len(loaded.Actions) != 0 || len(loaded.AllowedRoots) != 0 || loaded.WindowsLocalAccountsInventory {
		t.Fatal("exact password-only profile could not load or gained another grant", e)
	}
	c := newLocalRotationChannel(t, i)
	rollback, e := NewHostRollbackStore(t.TempDir(), i.TenantID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = RunOnceWithRoles(t.Context(), c, nil, loaded, nil, nil, rollback, []string{mtls.AgentRoleHost}, 1, 60); e != nil || !slices.Contains(c.kinds, KindWindowsLocalAccountRotation) || slices.Contains(c.kinds, "connector.deploy") {
		t.Fatal("password-only host did not claim exact native work", e)
	}
	profile.WindowsLocalAccountWrites = append(profile.WindowsLocalAccountWrites, profile.WindowsLocalAccountWrites[0])
	raw, _ = json.Marshal(profile)
	if e = root.WriteFile("host.json", raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = LoadHostProfile(name); e == nil {
		t.Fatal("duplicate native write grants accepted")
	}
}

func TestLocalAccountRotationExecutionRespectsCredentialDeadlineA268(t *testing.T) {
	for _, expired := range []bool{false, true} {
		i := localRotationIntent(t)
		c := newLocalRotationChannel(t, i)
		c.materialExpiry = time.Now().Add(10 * time.Second)
		if expired {
			c.materialExpiry = time.Now().Add(-time.Second)
		}
		success := runJob(t.Context(), c, nil, localRotationProfile(i), nil, nil, nil, rotationJob(t, i))
		if expired {
			if success || c.native.calls != 0 || c.report.Failure != "credential_unavailable" {
				t.Fatal("expired private material reached native execution")
			}
		} else if !success || !c.nativeDeadline.Equal(c.materialExpiry) {
			t.Fatal("native execution exceeded credential authorization deadline")
		}
		for _, value := range c.wire {
			if !bytes.Equal(value, make([]byte, len(value))) {
				t.Fatal("deadline handling retained wire material")
			}
		}
	}
}

func TestLocalAccountRotationWipesRejectedReplyBeforeReportingA268(t *testing.T) {
	i := localRotationIntent(t)
	c := newLocalRotationChannel(t, i)
	c.extra = true
	runJob(t.Context(), c, nil, localRotationProfile(i), nil, nil, nil, rotationJob(t, i))
	if c.wireLiveAtReport {
		t.Fatal("rejected credentials stayed alive while reporting over the network")
	}
}
