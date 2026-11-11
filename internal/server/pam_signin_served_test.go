// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/sshkeys"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/pamsignin"
)

const a274SignInsImage = "trstctl-sshd-signins-test:a274"

// startLabSSHSignIns builds and runs the A274 lab host (OpenSSH logging to
// syslog), installs adminPublic as root's key and reads the host key it
// generated, or skips when docker or the base image is not available.
func startLabSSHSignIns(t *testing.T, adminPublic []byte) labSSHAccounts {
	t.Helper()
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required: %v", err)
	}
	if out, err := exec.Command("docker", "build", "-q", "-t", a274SignInsImage, filepath.Join("testdata", "sshd-signins")).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Skipf("the lab host image did not build (offline?): %v\n%s", err, out)
	}
	created, err := exec.Command("docker", "run", "-d", "--rm", "-p", "127.0.0.1::22", a274SignInsImage).CombinedOutput() // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	if err != nil {
		t.Fatalf("docker run: %v %s", err, created)
	}
	lab := labSSHAccounts{id: strings.TrimSpace(string(created))}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", "-v", lab.id).Run() }) // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	if out, err := lab.shell("cat > /root/.ssh/authorized_keys && chmod 0600 /root/.ssh/authorized_keys", adminPublic); err != nil {
		t.Fatalf("install the administrator key: %v %s", err, out)
	}
	a201Await(t, "the lab host's sshd and syslog", func() bool {
		out, err := a201Exec(lab.id, "cat", "/etc/ssh/ssh_host_ed25519_key.pub")
		if err != nil {
			return false
		}
		info, err := sshkeys.ParsePublicKey([]byte(out))
		if err != nil {
			return false
		}
		lab.fingerprint = info.FingerprintSHA256
		_, err = a201Exec(lab.id, "sh", "-c", "pgrep -x sshd && pgrep -x rsyslogd")
		return err == nil
	})
	mapped, err := exec.Command("docker", "port", lab.id, "22/tcp").Output() // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	lab.addr = strings.TrimSpace(strings.Split(string(mapped), "\n")[0])
	return lab
}

type a274Finding struct {
	ID          string         `json:"id"`
	Kind        string         `json:"kind"`
	Ref         string         `json:"ref"`
	SourceID    string         `json:"source_id"`
	RiskScore   int            `json:"risk_score"`
	Provenance  string         `json:"provenance"`
	Fingerprint string         `json:"fingerprint"`
	Metadata    map[string]any `json:"metadata"`
}

// TestServedBypassDetectionOnALinuxHostA274: a pam_signin source watches the
// account a Linux host's unix provider manages. A sign-in with the account's
// password from outside trstctl raises a compromised-credential finding
// within the next collection, naming the account, its client address and
// how it signed in; the provider's own rotation of the account, which signs
// in with the new password to prove it, raises none; a re-collection
// refreshes, never repeats, the finding; another tenant sees nothing. The
// collector reads sign-in records only.
func TestServedBypassDetectionOnALinuxHostA274(t *testing.T) {
	ctx := context.Background()
	adminKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer adminKey.Destroy()
	adminPublic, err := crypto.SSHPublicKeyFromSigner(adminKey)
	if err != nil {
		t.Fatal(err)
	}
	der, err := adminKey.PKCS8()
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(der)
	lab := startLabSSHSignIns(t, adminPublic)
	const account, directPassword = "orders-single", "Direct-Outside-Pass-1"
	if out, err := lab.shell("chpasswd", []byte(account+":"+directPassword+"\n")); err != nil {
		t.Fatalf("set the account's password: %v %s", err, out)
	}
	tenant := uuid.NewString()
	adminPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	providers := []config.DynamicSecretProviderConfig{{TenantID: tenant, ID: "a274-host", Type: "unix", Addr: lab.addr, AdminUser: "root",
		HostKeyFingerprint: lab.fingerprint, PrivateKeyRef: writeServedCredentialFile(t, "a274-host-admin-key.pem", string(adminPEM)),
		AllowedRoles: []string{"host/single"}, RoleBindings: map[string]string{"host/single": account}, MaxTTL: "1h", AllowStaticRotation: true}}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: providers}, true); err != nil {
		t.Fatalf("the provider as configured: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(ctx, providers, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{tenant: registry.ForTenant(tenant)}
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, SignInRetention: time.Hour,
			Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	registerServedTenantID(t, h, tenant, "A274 bypass detection")
	// This proof collects right after each sign-in; how long a collection
	// waits before judging one is proven by A274-L1's test.
	h.srv.pam.signInSettle.Store(int64(time.Millisecond))
	tok := seedScopedToken(t, h.store, tenant, "discovery:read", "discovery:write", "secrets:read", "secrets:write")

	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, "a274-source", map[string]any{
		"name": "a274-host-signins", "kind": "pam_signin", "config": map[string]any{"provider_id": "a274-host", "lookback_seconds": 900}})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil || source.ID == "" {
		t.Fatalf("create the pam_signin source: %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, "a274-bad-source", map[string]any{
		"name": "a274-bad", "kind": "pam_signin", "config": map[string]any{"provider_id": "a274-host", "password": "never"}}); status != http.StatusBadRequest {
		t.Fatalf("a pam_signin source carrying another field: %d %s", status, body)
	}
	collect := func(key string) []a274Finding {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, key, map[string]any{"source_id": source.ID})
		var queued struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &queued) != nil || queued.ID == "" {
			t.Fatalf("queue %s: %d %s", key, status, body)
		}
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatalf("drain %s: %v", key, err)
		}
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, tok, nil)
		var run struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &run) != nil || run.Status != "succeeded" {
			t.Fatalf("run %s: %d %s", key, status, body)
		}
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?limit=100", tok, nil)
		var listed struct {
			Items []a274Finding `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &listed) != nil {
			t.Fatalf("findings after %s: %d %s", key, status, body)
		}
		if strings.Contains(string(body), directPassword) {
			t.Fatal("a password reached the findings")
		}
		var out []a274Finding
		for _, f := range listed.Items {
			if f.SourceID == source.ID {
				out = append(out, f)
			}
		}
		return out
	}
	accepted := func(want int) {
		t.Helper()
		a201Await(t, "the host's auth log", func() bool {
			out, err := a201Exec(lab.id, "sh", "-c", "grep -c 'Accepted password for "+account+" ' /var/log/auth.log")
			return err == nil && strings.TrimSpace(out) == strconv.Itoa(want)
		})
	}

	if got := collect("a274-before"); len(got) != 0 {
		t.Fatalf("findings before any sign-in: %+v", got)
	}
	// Someone signs in with the account's password, outside trstctl.
	target := crypto.SSHAccountTarget{Address: lab.addr, HostKeyFingerprint: lab.fingerprint}
	if err := crypto.VerifySSHAccountPassword(ctx, target, account, []byte(directPassword)); err != nil {
		t.Fatalf("the outside sign-in: %v", err)
	}
	accepted(1)
	got := collect("a274-after-direct")
	if len(got) != 1 {
		t.Fatalf("an outside sign-in raised %d findings: %+v", len(got), got)
	}
	f := got[0]
	signIn, _ := f.Metadata["sign_in"].(map[string]any)
	if f.Kind != "compromised_credential" || f.Ref != "pam:a274-host/"+account || f.RiskScore != 90 || f.Metadata["principal"] != account ||
		f.Metadata["detector"] != "pam_signin:sshd" || f.Metadata["ip"] == "" || f.Metadata["capability"] != "CAP-ITDR-02" || signIn["method"] != "password" {
		t.Fatalf("the bypass finding: %+v", f)
	}

	// The provider rotates the account in place and proves the new password
	// by signing in with it: explained by the rotation, no finding.
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", tok, "a274-seed",
		map[string]any{"name": "host/single", "value": `{"username":"orders-single","password":"unknown"}`}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed: %d %s", status, body)
	}
	status, body = secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/rotations", tok, "a274-rotate",
		map[string]any{"provider": "a274-host", "key": "host/single", "old_ref": "none", "acknowledge_single_phase": true})
	var queued struct {
		CommandID string `json:"command_id"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &queued) != nil {
		t.Fatalf("rotate: %d %s", status, body)
	}
	var rotation staticRotationCommandView
	for deadline := time.Now().Add(90 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		staticRotationDueFor(t, h, tenant)
		h.srv.dispatchOnce(ctx)
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/secrets/rotations/"+queued.CommandID, tok, nil)
		if status != http.StatusOK || json.Unmarshal(body, &rotation) != nil {
			t.Fatalf("read the rotation: %d %s", status, body)
		}
		if rotation.Terminal || time.Now().After(deadline) {
			break
		}
	}
	if rotation.Phase != "completed" || rotation.VerifyMode != "authenticated" {
		t.Fatalf("the rotation: %+v", rotation)
	}
	accepted(2)
	if got := collect("a274-after-rotation"); len(got) != 1 || got[0].ID != f.ID {
		t.Fatalf("after the rotation's own sign-in: %+v", got)
	}

	// The sign-ins themselves are recorded (A274 part 2), metadata only, for
	// the tenant's access readers: the outside one unexplained (its finding's
	// fingerprint), the rotation's proof explained by that rotation.
	signIns := func(token, query string) (int, []api.PAMSignIn) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/access/signins"+query, token, nil)
		if strings.Contains(string(body), directPassword) {
			t.Fatal("a password reached the recorded sign-ins")
		}
		var listed struct {
			Items []api.PAMSignIn `json:"items"`
		}
		if status == http.StatusOK && json.Unmarshal(body, &listed) != nil {
			t.Fatalf("the recorded sign-ins: %s", body)
		}
		return status, listed.Items
	}
	if status, _ := signIns(tok, ""); status != http.StatusForbidden {
		t.Fatalf("a token without access:read read the sign-ins: %d", status)
	}
	reader := seedScopedToken(t, h.store, tenant, "access:read")
	status, recorded := signIns(reader, "?provider_id=a274-host")
	if status != http.StatusOK || len(recorded) != 2 {
		t.Fatalf("the recorded sign-ins: %d %+v", status, recorded)
	}
	var direct, proof api.PAMSignIn
	for _, s := range recorded {
		if s.ExplainedBy == nil {
			direct = s
		} else {
			proof = s
		}
	}
	if direct.Fingerprint != f.Fingerprint || direct.Account != account || direct.Method != "password" || direct.Collector != "sshd" || direct.Source == "" ||
		proof.Account != account || proof.ExplainedBy == nil || proof.ExplainedBy.Kind != "rotation_check" || proof.ExplainedBy.Ref == "" ||
		!proof.At.After(direct.At) || !recorded[0].At.Equal(proof.At) {
		t.Fatalf("the outside sign-in and the rotation's proof, newest first: %+v", recorded)
	}
	if status, only := signIns(reader, "?unexplained=true"); status != http.StatusOK || len(only) != 1 || only[0].Fingerprint != f.Fingerprint {
		t.Fatalf("only the unexplained: %d %+v", status, only)
	}
	if status, none := signIns(reader, "?provider_id=another-provider"); status != http.StatusOK || len(none) != 0 {
		t.Fatalf("another provider's sign-ins: %d %+v", status, none)
	}
	if status, _ := signIns(reader, "?limit=0"); status != http.StatusBadRequest {
		t.Fatalf("a zero limit: %d", status)
	}

	// Past the configured retention the recorded sign-ins are purged; the
	// finding they raised stays.
	previousClock := h.srv.pam.clock
	h.srv.pam.clock = func() time.Time { return time.Now().UTC().Add(2 * time.Hour) }
	h.srv.pam.purgeExpiredSignIns(ctx)
	h.srv.pam.clock = previousClock
	if status, left := signIns(reader, ""); status != http.StatusOK || len(left) != 0 {
		t.Fatalf("sign-ins past the retention: %d %+v", status, left)
	}
	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?limit=100", tok, nil)
	if status != http.StatusOK || !strings.Contains(string(body), f.ID) {
		t.Fatalf("the finding after the purge: %d %s", status, body)
	}

	other := uuid.NewString()
	registerServedTenantID(t, h, other, "A274 isolation")
	otherToken := seedScopedToken(t, h.store, other, "discovery:read")
	if status, body := secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?limit=100", otherToken, nil); status != http.StatusOK || strings.Contains(string(body), account) {
		t.Fatalf("another tenant read the bypass finding: %d %s", status, body)
	}
	otherReader := seedScopedToken(t, h.store, other, "access:read")
	if status, theirs := signIns(otherReader, ""); status != http.StatusOK || len(theirs) != 0 {
		t.Fatalf("another tenant read the recorded sign-ins: %d %+v", status, theirs)
	}
}

// TestServedBypassDetectionOnADatabaseA274: a pam_signin source watches the
// two accounts the vaulted PostgreSQL provider rotates (A261). A connection
// with the vaulted account's DSN made outside trstctl raises a
// compromised-credential finding in the next collection; the gateway's
// connection for a reviewed session as the account, and a connection with
// a revealed check-out's credential, raise none.
func TestServedBypassDetectionOnADatabaseA274(t *testing.T) {
	ctx := context.Background()
	f := startGatewayFixture(t, gatewayFixtureOptions{vaulted: true})
	h := f.h
	// This proof collects right after each sign-in; how long a collection
	// waits before judging one is proven by A274-L1's test.
	h.srv.pam.signInSettle.Store(int64(time.Millisecond))
	custodian := seedScopedTokenSubject(t, h.store, h.tenant, "a274-db-secrets", "secrets:read", "secrets:write")
	registrar := seedScopedTokenSubject(t, h.store, h.tenant, "a274-db-registrar", "access:read", "access:targets.write")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "a274-db-requester", "access:read", "access:sessions.open")
	reviewers := []string{
		seedScopedTokenSubject(t, h.store, h.tenant, "a274-db-reviewer-1", "access:read", "access:approve"),
		seedScopedTokenSubject(t, h.store, h.tenant, "a274-db-reviewer-2", "access:read", "access:approve"),
	}
	watcher := seedScopedTokenSubject(t, h.store, h.tenant, "a274-db-watcher", "discovery:read", "discovery:write")
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/secrets/store", custodian, "a274-db-seed",
		map[string]any{"name": twoUserRole, "value": f.vaultDSN}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("seed the account secret: %d %s", status, body)
	}
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", registrar, "a274-db-register",
		map[string]any{"id": "orders-vault", "target_type": "postgres", "provider_id": "pam-pg-vault", "allowed_roles": []string{twoUserRole},
			"gateway_agent_id": agentRowID(servedTestTenant, "role-agent"), "gateway_address": f.gatewayAddr, "account_secret": twoUserRole}); status != http.StatusCreated {
		t.Fatalf("register the vaulted target = %d %s", status, body)
	}
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/sources", watcher, "a274-db-source", map[string]any{
		"name": "a274-orders-signins", "kind": "pam_signin", "config": map[string]any{"provider_id": "pam-pg-vault", "lookback_seconds": 900}})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil || source.ID == "" {
		t.Fatalf("create the pam_signin source: %d %s", status, body)
	}
	collect := func(key string) []a274Finding {
		t.Helper()
		status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/runs", watcher, key, map[string]any{"source_id": source.ID})
		var queued struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &queued) != nil || queued.ID == "" {
			t.Fatalf("queue %s: %d %s", key, status, body)
		}
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatalf("drain %s: %v", key, err)
		}
		status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, watcher, nil)
		if status != http.StatusOK || !strings.Contains(string(body), `"status":"succeeded"`) {
			t.Fatalf("run %s: %d %s", key, status, body)
		}
		status, body = secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/discovery/findings?limit=100", watcher, nil)
		var listed struct {
			Items []a274Finding `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &listed) != nil {
			t.Fatalf("findings after %s: %d %s", key, status, body)
		}
		var out []a274Finding
		for _, finding := range listed.Items {
			if finding.SourceID == source.ID {
				out = append(out, finding)
			}
		}
		return out
	}
	connect := func(dsn string) func() {
		t.Helper()
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		if _, err := conn.Exec(ctx, "SELECT 1"); err != nil {
			t.Fatalf("query: %v", err)
		}
		return func() { _ = conn.Close(context.Background()) }
	}

	// An earlier test in this process may have used these accounts in this
	// tenant (the fixture's provider and accounts are shared): its spans
	// explain sign-ins for the clock-skew allowance after they end, so the
	// outside connection waits that out.
	src, err := h.srv.pam.signInSource(h.tenant, "pam-pg-vault")
	if err != nil {
		t.Fatal(err)
	}
	windows, err := h.srv.pam.signInWindows(ctx, h.tenant, src, src.DynamicSecretManagedAccounts(), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var latest time.Time
	for _, w := range windows {
		if w.To.After(latest) {
			latest = w.To
		}
	}
	if wait := time.Until(latest.Add(pamsignin.DefaultSlack + time.Second)); wait > 0 {
		if wait > 5*time.Minute {
			t.Fatalf("an earlier span of these accounts lasts until %s", latest)
		}
		time.Sleep(wait)
	}

	// Someone uses the vaulted DSN outside trstctl.
	closeDirect := connect(f.vaultDSN)
	got := collect("a274-db-direct")
	closeDirect()
	if len(got) != 1 || got[0].Metadata["principal"] != twoUserAccountA || got[0].Metadata["detector"] != "pam_signin:pg_stat_activity" ||
		got[0].Kind != "compromised_credential" || got[0].Metadata["ip"] == "" {
		t.Fatalf("an outside connection raised: %+v", got)
	}
	direct := got[0].ID

	// The gateway signs in as the account for a reviewed session.
	session := f.open("a274-db-session", map[string]any{"target_type": "postgres", "target_id": "orders-vault", "role": twoUserRole, "ttl_seconds": 120})
	tunnel, stopTunnel := f.postgresTunnel(session)
	closeGateway := connect("postgres://client@" + tunnel + "/postgres?sslmode=disable")
	got = collect("a274-db-gateway")
	closeGateway()
	stopTunnel()
	if len(got) != 1 || got[0].ID != direct {
		t.Fatalf("a gateway session's sign-in raised: %+v", got)
	}

	// A reviewed check-out reveals the credential; its holder connects.
	status, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts", requester, "a274-db-checkout",
		map[string]any{"request_id": uuid.NewString(), "target_type": "postgres", "target_id": "orders-vault",
			"reason": "INC-4471 reconcile the orders ledger by hand", "ttl_seconds": 120})
	var review struct {
		RequestID, ApprovalRequestID, IntentDigest string
		RequiredApprovals                          int
	}
	var reviewJSON struct {
		RequestID         string `json:"request_id"`
		ApprovalRequestID string `json:"approval_request_id"`
		IntentDigest      string `json:"intent_digest"`
		RequiredApprovals int    `json:"required_approvals"`
	}
	if status != http.StatusAccepted || json.Unmarshal(raw, &reviewJSON) != nil {
		t.Fatalf("request a check-out = %d %s", status, raw)
	}
	review.RequestID, review.ApprovalRequestID, review.IntentDigest, review.RequiredApprovals = reviewJSON.RequestID, reviewJSON.ApprovalRequestID, reviewJSON.IntentDigest, reviewJSON.RequiredApprovals
	for i, reviewer := range reviewers[:review.RequiredApprovals] {
		if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/approval-requests/"+review.ApprovalRequestID+"/approvals",
			reviewer, review.RequestID+"-approve-"+strconv.Itoa(i), map[string]any{"intent_digest": review.IntentDigest}); status != http.StatusOK {
			t.Fatalf("review %d = %d %s", i+1, status, body)
		}
	}
	status, raw = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/checkouts/"+review.RequestID+"/reveal", requester, "a274-db-reveal",
		map[string]any{"approval_request_id": review.ApprovalRequestID, "intent_digest": review.IntentDigest})
	var revealed struct {
		Credential string `json:"credential"`
	}
	if status != http.StatusOK || json.Unmarshal(raw, &revealed) != nil || revealed.Credential == "" {
		t.Fatalf("reveal = %d %s", status, raw)
	}
	closeCheckout := connect(revealed.Credential)
	got = collect("a274-db-checkout-run")
	closeCheckout()
	if len(got) != 1 || got[0].ID != direct {
		t.Fatalf("a revealed check-out's sign-in raised: %+v", got)
	}
}

// TestServedBypassDetectionOnMySQLA274: a pam_signin source watches the
// account a MySQL provider's static role binds. MySQL keeps no connection
// start time, so its collector dates a connection when a run first sees it:
// an outside connection raises one compromised-credential finding and one
// recorded sign-in, a later run that sees it still open refreshes them
// rather than repeating them, a second outside connection is a second
// sign-in, and neither another account's connection nor the collector's own
// administrator connection is reported.
func TestServedBypassDetectionOnMySQLA274(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	if out, err := exec.Command("docker", "image", "inspect", a201MySQLImage).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Skipf("the pinned image %s is not present locally: %v\n%s", a201MySQLImage, err, out)
	}
	ctx := context.Background()
	id, addr := a201Container(t, "3306", "-e", "MYSQL_ROOT_PASSWORD=a274-root", "-e", "MYSQL_DATABASE=app", a201MySQLImage)
	a256AwaitLog(t, id, "MySQL init process done")
	asUser := func(user, password, sql string) (string, error) {
		return a201Exec(id, "mysql", "--protocol=TCP", "-h", "127.0.0.1", "-u"+user, "-p"+password, "-N", "-e", sql)
	}
	a201Await(t, "MySQL", func() bool { _, err := asUser("root", "a274-root", "SELECT 1"); return err == nil })
	const account, outsidePassword = "app_reader", "Outside-Pass-1"
	if out, err := asUser("root", "a274-root", "CREATE USER 'broker'@'%' IDENTIFIED BY 'broker-pass'; GRANT ALL ON *.* TO 'broker'@'%' WITH GRANT OPTION;"+
		"CREATE USER '"+account+"'@'%' IDENTIFIED BY '"+outsidePassword+"'; GRANT SELECT ON app.* TO '"+account+"'@'%';"+
		"CREATE USER 'bystander'@'%' IDENTIFIED BY 'bystander-pass'; GRANT SELECT ON app.* TO 'bystander'@'%';"); err != nil {
		t.Fatalf("create the accounts: %v %s", err, out)
	}
	tenant := uuid.NewString()
	providers := []config.DynamicSecretProviderConfig{{TenantID: tenant, ID: "a274-mysql", Type: "mysql",
		AdminDSNRef: writeServedCredentialFile(t, "a274-mysql-admin-dsn", "broker:broker-pass@tcp("+addr+")/app\n"), Database: "app", Addr: addr,
		AccountHost: "%", AllowWildcardAccountHost: true, AllowedRoles: []string{"db/reader"}, RoleBindings: map[string]string{"db/reader": account},
		RoleAccess:          map[string]string{"db/reader": "read"},
		AllowStaticRotation: true, MaxTTL: "1h", UsernamePrefix: "a274"}}
	if err := config.ValidateSecretIntegrations(config.SecretIntegrationsConfig{DynamicProviders: providers}, true); err != nil {
		t.Fatalf("the provider as configured: %v", err)
	}
	registry, err := dynamicSecretProvidersFromConfig(ctx, providers, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newServedHarness(t, config.Protocols{}, withSecretsEnabled(t, nil), func(d *Deps) {
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{tenant: registry.ForTenant(tenant)}
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, Attestors: []attest.Attestor{servedPAMAttestor{}}}
	})
	registerServedTenantID(t, h, tenant, "A274 MySQL bypass detection")
	tok := seedScopedToken(t, h.store, tenant, "discovery:read", "discovery:write")
	reader := seedScopedToken(t, h.store, tenant, "access:read")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/sources", tok, "a274-mysql-source", map[string]any{
		"name": "a274-mysql-signins", "kind": "pam_signin", "config": map[string]any{"provider_id": "a274-mysql", "lookback_seconds": 900}})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil || source.ID == "" {
		t.Fatalf("create the pam_signin source: %d %s", status, body)
	}
	collect := func(key string) []a274Finding {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/discovery/runs", tok, key, map[string]any{"source_id": source.ID})
		var queued struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &queued) != nil || queued.ID == "" {
			t.Fatalf("queue %s: %d %s", key, status, body)
		}
		if err := h.srv.Drain(ctx); err != nil {
			t.Fatalf("drain %s: %v", key, err)
		}
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/runs/"+queued.ID, tok, nil)
		if status != http.StatusOK || !strings.Contains(string(body), `"status":"succeeded"`) {
			t.Fatalf("run %s: %d %s", key, status, body)
		}
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/discovery/findings?limit=100", tok, nil)
		var listed struct {
			Items []a274Finding `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &listed) != nil || strings.Contains(string(body), outsidePassword) {
			t.Fatalf("findings after %s: %d %s", key, status, body)
		}
		var out []a274Finding
		for _, f := range listed.Items {
			if f.SourceID == source.ID {
				out = append(out, f)
			}
		}
		return out
	}
	recorded := func() []api.PAMSignIn {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodGet, "/api/v1/access/signins?provider_id=a274-mysql", reader, nil)
		var listed struct {
			Items []api.PAMSignIn `json:"items"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &listed) != nil {
			t.Fatalf("the recorded sign-ins: %d %s", status, body)
		}
		return listed.Items
	}
	connect := func(user, password string) func() {
		t.Helper()
		db, err := dynsecret.OpenMySQLExecutor(ctx, []byte(user+":"+password+"@tcp("+addr+")/app"))
		if err != nil {
			t.Fatalf("connect as %s: %v", user, err)
		}
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatalf("hold a connection as %s: %v", user, err)
		}
		if err := conn.PingContext(ctx); err != nil {
			t.Fatalf("ping as %s: %v", user, err)
		}
		return func() { _ = conn.Close(); _ = db.Close() }
	}

	if got := collect("a274-mysql-before"); len(got) != 0 {
		t.Fatalf("findings before any outside connection: %+v", got)
	}
	closeBystander := connect("bystander", "bystander-pass")
	defer closeBystander()
	closeOutside := connect(account, outsidePassword)
	defer closeOutside()
	got := collect("a274-mysql-outside")
	if len(got) != 1 || got[0].Kind != "compromised_credential" || got[0].Ref != "pam:a274-mysql/"+account || got[0].Metadata["principal"] != account ||
		got[0].Metadata["detector"] != "pam_signin:performance_schema_threads" || got[0].Metadata["ip"] == "" {
		t.Fatalf("an outside connection raised: %+v", got)
	}
	first := got[0]
	// The next run starts in a later second, so it dates the connection anew.
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(1100 * time.Millisecond)))
	if again := collect("a274-mysql-still-open"); len(again) != 1 || again[0].ID != first.ID || again[0].Fingerprint != first.Fingerprint {
		t.Fatalf("a run that sees the same connection again repeated it: %+v", again)
	}
	signIns := recorded()
	if len(signIns) != 1 || signIns[0].Fingerprint != first.Fingerprint || signIns[0].Account != account || signIns[0].Earliest == nil ||
		!signIns[0].Earliest.Before(signIns[0].At) || signIns[0].ExplainedBy != nil || signIns[0].Collector != "performance_schema_threads" ||
		!signIns[0].LastSeenAt.After(signIns[0].At) {
		t.Fatalf("the recorded connection (dated when first seen, seen again since): %+v", signIns)
	}
	closeSecond := connect(account, outsidePassword)
	defer closeSecond()
	if got := collect("a274-mysql-second"); len(got) != 2 {
		t.Fatalf("a second outside connection: %+v", got)
	}
	if signIns := recorded(); len(signIns) != 2 {
		t.Fatalf("the recorded connections: %+v", signIns)
	}
}
