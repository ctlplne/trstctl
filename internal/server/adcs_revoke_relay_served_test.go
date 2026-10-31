// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const adcsRevocationCA = `CORP-DC01\Corp Issuing CA`

// adcsCAAdminStandIn is the CA side certutil drives from a domain-joined
// relay: revoke a serial, publish a CRL signed by the AD CS stand-in's issuing
// CA, read a row's disposition back, and serve the CRL at its distribution
// point the way a relying party fetches it.
type adcsCAAdminStandIn struct {
	mu      sync.Mutex
	certsrv *adcsCertsrvStandIn
	issued  map[string]bool
	revoked map[string]int
	crl     []byte
	number  int64
	failCRL bool
}

func (a *adcsCAAdminStandIn) serve(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	serial := strings.ToLower(r.URL.Query().Get("serial"))
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/admin/revoke":
		reason, err := strconv.Atoi(r.URL.Query().Get("reason"))
		if !a.issued[serial] || err != nil || reason < 0 || reason > 5 {
			http.Error(w, "CertUtil: -revoke command FAILED", http.StatusNotFound)
			return
		}
		a.revoked[serial] = reason
	case r.Method == http.MethodPost && r.URL.Path == "/admin/crl":
		if a.failCRL {
			http.Error(w, "CertUtil: -CRL command FAILED: 0x800706ba (WIN32: 1722 RPC_S_SERVER_UNAVAILABLE)", http.StatusServiceUnavailable)
			return
		}
		entries := make([]crypto.RevokedSerial, 0, len(a.revoked))
		for s, reason := range a.revoked {
			entries = append(entries, crypto.RevokedSerial{Serial: s, RevokedAt: time.Now().UTC(), Reason: reason})
		}
		a.number++
		now := time.Now().UTC()
		crl, err := crypto.CreateCRL(a.certsrv.caDER, a.certsrv.caKey, entries, a.number, now, now.Add(time.Hour))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		a.crl = crl
	case r.Method == http.MethodGet && r.URL.Path == "/admin/disposition":
		if !a.issued[serial] {
			http.NotFound(w, r)
			return
		}
		if _, ok := a.revoked[serial]; ok {
			_, _ = io.WriteString(w, "21 -- Revoked")
			return
		}
		_, _ = io.WriteString(w, "20 -- Issued")
	case r.Method == http.MethodGet && r.URL.Path == "/CertEnroll/Corp-Issuing-CA.crl":
		if a.crl == nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(a.crl)
	default:
		http.NotFound(w, r)
	}
}

// writeCertutilRevokeStandIn is certutil.exe on the domain-joined relay, as a
// POSIX script that drives the CA stand-in.
func writeCertutilRevokeStandIn(t *testing.T, adminURL string) string {
	t.Helper()
	script := filepath.Join(t.TempDir(), "certutil")
	body := `#!/bin/sh
A='` + adminURL + `'
[ "$1" = -config ] && [ "$2" = '` + adcsRevocationCA + `' ] || exit 2
case "$3" in
-revoke) curl -fsS -o /dev/null -X POST "$A/admin/revoke?serial=$4&reason=$5" ;;
-CRL) curl -fsS -o /dev/null -X POST "$A/admin/crl" ;;
-view) s="${5#SerialNumber=}"; d=$(curl -fsS "$A/admin/disposition?serial=$s") || exit 1
  printf '"Serial Number","Request Disposition"\n"%s","%s"\n' "$s" "$d" ;;
*) exit 2 ;;
esac
`
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { // #nosec G306 -- a test-owned executable stand-in (CWE-276).
		t.Fatal(err)
	}
	return script
}

// adcsRevocationConfig is the adcs issuer with its revocation relay.
func adcsRevocationConfig(t *testing.T, certsrvURL, relayName string) []ExternalCA {
	t.Helper()
	endpoint, err := url.Parse(certsrvURL)
	if err != nil {
		t.Fatal(err)
	}
	address := netip.MustParseAddr(endpoint.Hostname())
	entry := config.ExternalCAConfig{
		ID: "corp-adcs-web", Type: "adcs", Name: "Corp AD CS (WebServer template)", TenantID: servedTestTenant,
		Endpoint: certsrvURL + "/certsrv", CAConfig: adcsRevocationCA, Template: "WebServer", PollInterval: "10ms",
		RevocationRelay: relayName,
		Network: config.ExternalCANetworkConfig{AllowInsecureHTTP: true, AllowPrivateEndpoint: true,
			PrivateEgressCIDRs: []string{netip.PrefixFrom(address, 32).String()}, Timeout: "10s"},
	}
	if err := config.ValidateExternalCAs([]config.ExternalCAConfig{entry}); err != nil {
		t.Fatalf("the AD CS issuer with a revocation relay does not validate: %v", err)
	}
	upstreams, err := externalCAsFromConfig(context.Background(), []config.ExternalCAConfig{entry}, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("configure the AD CS external CA: %v", err)
	}
	return upstreams
}

// recordADCSIssuedLeaf records a certificate the AD CS stand-in issued, the
// way an issuance through the adcs issuer records it.
func recordADCSIssuedLeaf(t *testing.T, h *issuanceDispatcherHarness, certsrv *adcsCertsrvStandIn, owner, name, key string) store.Certificate {
	t.Helper()
	leafDER, err := crypto.SignLeafFromCSR(certsrv.caDER, certsrv.caKey, serverTestCSR(t, name, nil), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	info, err := certinfo.Inspect(leafPEM)
	if err != nil {
		t.Fatal(err)
	}
	c := store.Certificate{OwnerID: &owner, Subject: info.Subject, SANs: info.DNSNames, Issuer: info.Issuer, Serial: info.SerialNumber,
		Fingerprint: info.SHA256Fingerprint, KeyAlgorithm: info.KeyAlgorithm, NotBefore: &info.NotBefore, NotAfter: &info.NotAfter,
		Source: "external-ca:corp-adcs-web", CertificateDER: leafDER, CertificatePEM: leafPEM, IssuanceIdempotencyKey: "external-test:" + key}
	fact := projections.CertificateRecorded{ID: uuid.NewString(), Source: c.Source, Subject: c.Subject, SANs: c.SANs, Issuer: c.Issuer,
		Serial: c.Serial, Fingerprint: c.Fingerprint, KeyAlgorithm: c.KeyAlgorithm, NotBefore: c.NotBefore, NotAfter: c.NotAfter,
		CertificateDER: c.CertificateDER, CertificatePEM: c.CertificatePEM,
		IssuanceIdempotencyKey: c.IssuanceIdempotencyKey, IssuanceRequestBinding: strings.Repeat("a", 64)}
	payload, err := json.Marshal(fact)
	if err != nil {
		t.Fatal(err)
	}
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(h.tenant+"\x00certificate.recorded\x00"+c.IssuanceIdempotencyKey)).String()
	event, err := h.log.Append(t.Context(), events.Event{ID: eventID, TenantID: h.tenant, Type: projections.EventCertificateRecorded, Data: payload})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(h.store).Apply(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	c.Source, c.IssuanceIdempotencyKey = "issued", "agentcsr:"+key
	recorded, err := h.orch.RecordCertificate(t.Context(), h.tenant, c)
	if err != nil {
		t.Fatal(err)
	}
	return recorded
}

func adcsRevokeAttempts(t *testing.T, h *roleHarness) int {
	t.Helper()
	var n int
	if err := h.store.SystemPool().QueryRow(t.Context(), `SELECT count(*) FROM outbox WHERE tenant_id=$1 AND destination='adcs.revoke'`, h.tenant).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A162 / P11 Done-when: a revoke through trstctl shows on the AD CS CRL. An
// operator revokes a certificate the adcs issuer issued; the revocation's
// outbox delivery hands it to the issuer's domain-joined relay, whose
// production loop runs certutil to revoke at the CA, publish a new CRL and read
// the row back; only that checked report lets the delivery record the
// certificate revoked, and the CRL a relying party fetches from the CA's
// distribution point names the serial with the reason.
func TestServedRevokeThroughTrstctlShowsOnTheADCSCRL(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the certutil stand-in is a POSIX shell script")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("the certutil stand-in drives the CA stand-in with curl")
	}
	certsrvStandIn, certsrv := newADCSCertsrvStandIn(t)
	admin := &adcsCAAdminStandIn{certsrv: certsrvStandIn, issued: map[string]bool{}, revoked: map[string]int{}}
	adminSrv := httptest.NewServer(http.HandlerFunc(admin.serve))
	t.Cleanup(adminSrv.Close)
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{relay.KindADCSRevoke}, func(d *Deps) {
		d.ExternalCAs = adcsRevocationConfig(t, certsrv.URL, "role-agent")
	})
	if h.agent != "role-agent" || h.tenant != servedTestTenant {
		t.Fatalf("harness relay %q in tenant %q; the issuer names role-agent in %s", h.agent, h.tenant, servedTestTenant)
	}
	ctx := t.Context()
	previous := relay.CertutilPath
	t.Cleanup(func() { relay.CertutilPath = previous })
	relay.CertutilPath = writeCertutilRevokeStandIn(t, adminSrv.URL)

	dispatcher := h.srv.obHandler.(*issuanceDispatcher)
	i := &issuanceDispatcherHarness{store: h.store, log: h.log, orch: h.srv.orch, outbox: h.srv.outbox, handler: dispatcher, tenant: h.tenant}
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "service", "AD CS revocation", "")
	if err != nil {
		t.Fatal(err)
	}
	selected := recordADCSIssuedLeaf(t, i, certsrvStandIn, owner.ID, "web01.corp.example", "a162-selected")
	admin.issued[strings.ToLower(selected.Serial)] = true
	token := seedScopedToken(t, h.store, h.tenant, "certs:issue", "certs:read", "identities:write")
	status, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/certificates/bulk-revoke", token, "a162-adcs-revoke",
		map[string]any{"certificate_ids": []string{selected.ID}, "reason": "superseded"})
	if status != http.StatusOK || !bytes.Contains(raw, []byte(`"total_queued":1`)) {
		t.Fatalf("bulk revoke of an AD CS certificate = %d %s; want it queued for the issuer", status, raw)
	}
	row := pendingOutboxByDestination(t, i, "revocation.publish")
	message := orchestrator.Message{ID: row.ID, TenantID: h.tenant, Destination: row.Destination, Payload: row.Payload, IdempotencyKey: row.IdempotencyKey}
	for range 2 {
		if err := dispatcher.Deliver(ctx, message); !orchestrator.IsDeliveryDeferred(err) {
			t.Fatalf("delivery before the relay reports = %v; want a budget-neutral wait", err)
		}
	}
	if n := adcsRevokeAttempts(t, h); n != 1 {
		t.Fatalf("relay revocation attempts = %d; want one while it waits", n)
	}
	if current, err := h.store.GetCertificate(ctx, h.tenant, selected.ID); err != nil || current.Status != "active" {
		t.Fatalf("certificate before the relay reports = %+v %v; want still active", current.Status, err)
	}

	channel := &sshCollectionServedChannel{t: t, h: h}
	if count, err := relay.RunOnce(ctx, channel, http.DefaultClient, 1, 120); err != nil || count != 1 {
		t.Fatalf("production relay = %d %v reports %+v", count, err, channel.reports)
	}
	if err := dispatcher.Deliver(ctx, message); err != nil {
		t.Fatalf("delivery after the relay's checked report = %v", err)
	}
	current, err := h.store.GetCertificate(ctx, h.tenant, selected.ID)
	if err != nil || current.Status != "revoked" || current.RevocationReason != "superseded" {
		t.Fatalf("certificate after the AD CS revocation = %s/%s %v", current.Status, current.RevocationReason, err)
	}
	resp, err := http.Get(adminSrv.URL + "/CertEnroll/Corp-Issuing-CA.crl") // #nosec G107 -- the test's own CA stand-in (CWE-918).
	if err != nil {
		t.Fatal(err)
	}
	crlDER, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	crl, err := crypto.ParseCRL(crlDER, certsrvStandIn.caDER)
	if err != nil {
		t.Fatalf("the AD CS CRL does not verify under the AD CS issuing CA: %v", err)
	}
	onCRL := false
	for _, entry := range crl.Revoked {
		if entry.Serial == strings.TrimLeft(strings.ToLower(selected.Serial), "0") && entry.Reason == 4 {
			onCRL = true
		}
	}
	if !onCRL {
		t.Fatalf("serial %s is not on the AD CS CRL with reason superseded: %+v", selected.Serial, crl.Revoked)
	}
	if err := dispatcher.Deliver(ctx, message); err != nil || adcsRevokeAttempts(t, h) != 1 {
		t.Fatalf("a replayed delivery = %v with %d attempts; want no second revocation", err, adcsRevokeAttempts(t, h))
	}
}

// A relay that cannot finish (here the CA cannot publish its CRL) leaves the
// certificate active with the reason, spends one delivery attempt, and the
// next delivery queues a fresh relay attempt that completes it.
func TestServedADCSRelayRevocationFailureIsRetriedOnTheRevocationsBackoff(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the certutil stand-in is a POSIX shell script")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("the certutil stand-in drives the CA stand-in with curl")
	}
	certsrvStandIn, certsrv := newADCSCertsrvStandIn(t)
	admin := &adcsCAAdminStandIn{certsrv: certsrvStandIn, issued: map[string]bool{}, revoked: map[string]int{}, failCRL: true}
	adminSrv := httptest.NewServer(http.HandlerFunc(admin.serve))
	t.Cleanup(adminSrv.Close)
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleNetwork}, []string{relay.KindADCSRevoke}, func(d *Deps) {
		d.ExternalCAs = adcsRevocationConfig(t, certsrv.URL, "role-agent")
	})
	ctx := t.Context()
	previous := relay.CertutilPath
	t.Cleanup(func() { relay.CertutilPath = previous })
	relay.CertutilPath = writeCertutilRevokeStandIn(t, adminSrv.URL)
	dispatcher := h.srv.obHandler.(*issuanceDispatcher)
	i := &issuanceDispatcherHarness{store: h.store, log: h.log, orch: h.srv.orch, outbox: h.srv.outbox, handler: dispatcher, tenant: h.tenant}
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "service", "AD CS revocation retry", "")
	if err != nil {
		t.Fatal(err)
	}
	selected := recordADCSIssuedLeaf(t, i, certsrvStandIn, owner.ID, "web02.corp.example", "a162-retry")
	admin.issued[strings.ToLower(selected.Serial)] = true
	token := seedScopedToken(t, h.store, h.tenant, "certs:issue", "certs:read", "identities:write")
	if status, raw := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/certificates/bulk-revoke", token, "a162-adcs-retry",
		map[string]any{"certificate_ids": []string{selected.ID}, "reason": "keyCompromise"}); status != http.StatusOK {
		t.Fatalf("bulk revoke = %d %s", status, raw)
	}
	row := pendingOutboxByDestination(t, i, "revocation.publish")
	message := orchestrator.Message{ID: row.ID, TenantID: h.tenant, Destination: row.Destination, Payload: row.Payload, IdempotencyKey: row.IdempotencyKey}
	if err := dispatcher.Deliver(ctx, message); !orchestrator.IsDeliveryDeferred(err) {
		t.Fatalf("first delivery = %v; want a wait for the relay", err)
	}
	channel := &sshCollectionServedChannel{t: t, h: h}
	if count, err := relay.RunOnce(ctx, channel, http.DefaultClient, 1, 120); err != nil || count != 0 || len(channel.reports) != 1 {
		t.Fatalf("relay with the CRL unavailable = %d %v reports %d", count, err, len(channel.reports))
	}
	err = dispatcher.Deliver(ctx, message)
	if err == nil || orchestrator.IsDeliveryDeferred(err) || !strings.Contains(err.Error(), "could not publish a new CRL") {
		t.Fatalf("delivery after a failed relay attempt = %v; want a counted failure naming the relay's reason", err)
	}
	if current, err := h.store.GetCertificate(ctx, h.tenant, selected.ID); err != nil || current.Status != "active" {
		t.Fatalf("certificate after a failed relay attempt = %s %v; want still active", current.Status, err)
	}
	if n := adcsRevokeAttempts(t, h); n != 2 {
		t.Fatalf("relay attempts after one failure = %d; want the next one queued", n)
	}
	admin.mu.Lock()
	admin.failCRL = false
	admin.mu.Unlock()
	if count, err := relay.RunOnce(ctx, channel, http.DefaultClient, 1, 120); err != nil || count != 1 {
		t.Fatalf("relay after the CA recovers = %d %v", count, err)
	}
	if err := dispatcher.Deliver(ctx, message); err != nil {
		t.Fatal(err)
	}
	if current, err := h.store.GetCertificate(ctx, h.tenant, selected.ID); err != nil || current.Status != "revoked" || current.RevocationReason != "keyCompromise" {
		t.Fatalf("certificate after the retried revocation = %s/%s %v", current.Status, current.RevocationReason, err)
	}
}
