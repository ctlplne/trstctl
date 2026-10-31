// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

const adcsCertutilViewCSV = `"Issued Request ID","Request Disposition","Serial Number","Certificate Effective Date","Certificate Expiration Date","Issued Common Name","Certificate Template","Requester Name","Revocation Date"
"2","20 -- Issued","1a00000002","10/1/2026 9:00 AM","10/1/2027 9:00 AM","web01.corp.example","WebServer","CORP\svc-web","EMPTY"
"3","21 -- Revoked","1a00000003","10/1/2026 9:00 AM","10/1/2027 9:00 AM","web02.corp.example","WebServer","CORP\svc-web","10/15/2026 2:00 PM"
"4","9 -- Taken Under Submission","EMPTY","EMPTY","EMPTY","EMPTY","WebServer","CORP\alice","EMPTY"
"5","20 -- Issued","1a00000005","10/1/2026 9:00 AM","EMPTY","laptop-9.corp.example","Machine","CORP\LAPTOP-9$","EMPTY"
"EMPTY","30 -- Error","EMPTY","EMPTY","EMPTY","EMPTY","EMPTY","CORP\bob","EMPTY"
`

// writeCertutilStandIn installs a POSIX stand-in for certutil.exe on a
// domain-joined relay: it prints the CSV view for the expected CA, or fails.
func writeCertutilStandIn(t *testing.T, dir, caConfig string, fail bool) string {
	t.Helper()
	data := filepath.Join(dir, "view.csv")
	if err := os.WriteFile(data, []byte(adcsCertutilViewCSV), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "certutil")
	body := "#!/bin/sh\n[ \"$1\" = -config ] && [ \"$2\" = '" + caConfig + "' ] && [ \"$3\" = -view ] || exit 2\n"
	if fail {
		body += "echo 'CertUtil: -view command FAILED: 0x80070005 (WIN32: 5 ERROR_ACCESS_DENIED)' >&2\nexit 1\n"
	} else {
		body += "cat '" + data + "'\n"
	}
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { // #nosec G306 -- a test-owned executable stand-in (CWE-276).
		t.Fatal(err)
	}
	return script
}

type adcsDatabaseReadBack struct {
	Items []struct {
		CAConfig     string `json:"ca_config"`
		Issued       int    `json:"issued"`
		Pending      int    `json:"pending"`
		Revoked      int    `json:"revoked"`
		Unparsed     int    `json:"unparsed"`
		Total        int    `json:"total"`
		RowsRead     int    `json:"rows_read"`
		RowsRejected int    `json:"rows_rejected"`
		Source       string `json:"source"`
	} `json:"items"`
	Collections []struct {
		CollectionID string `json:"collection_id"`
		CAConfig     string `json:"ca_config"`
		RelayAgentID string `json:"relay_agent_id"`
		Status       string `json:"status"`
		LastError    string `json:"last_error"`
		CompletedAt  string `json:"completed_at"`
	} `json:"collections"`
}

// readADCSDatabases reads the served list and keeps only caConfig's rows: the
// served tenant is shared with other tests.
func readADCSDatabases(t *testing.T, h *roleHarness, token, caConfig string) adcsDatabaseReadBack {
	t.Helper()
	code, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/adcs/ca-database", token, nil)
	var all, out adcsDatabaseReadBack
	if code != http.StatusOK || json.Unmarshal(body, &all) != nil {
		t.Fatalf("list = %d %s", code, body)
	}
	for _, item := range all.Items {
		if item.CAConfig == caConfig {
			out.Items = append(out.Items, item)
		}
	}
	for _, read := range all.Collections {
		if read.CAConfig == caConfig {
			out.Collections = append(out.Collections, read)
		}
	}
	return out
}

// A162 Done-when: relay-side certutil collection. An operator asks one exact
// domain-joined relay to read a CA's database; the production relay loop runs
// certutil with a fixed argument vector, returns per-disposition counts only,
// and the control plane records them against the queued read. A failed read is
// visible with the relay's reason and leaves the previous counts in place.
func TestServedRelayReadsAnADCSCADatabaseWithCertutil(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the certutil stand-in is a POSIX shell script")
	}
	const caConfig = `ca01.corp.example\CORP-CA`
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, relay.KindADCSDatabase)
	ctx := t.Context()
	token := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")
	relayID := agentRowID(h.tenant, h.agent)
	request := map[string]any{"ca_config": caConfig, "relay_agent_id": relayID}

	// A relay that has not advertised certutil cannot be handed the read.
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "a162", Status: "active",
		Executors: &transport.ExecutorReport{Version: "a162", Kinds: []transport.ExecutorKind{{Kind: relay.KindADCSDatabase, MissingFlags: []string{"--adcs-certutil"}}}}}); err != nil {
		t.Fatal(err)
	}
	if code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/adcs/ca-database/collect", token, "a162-no-certutil", request); code != http.StatusConflict || !strings.Contains(string(body), "--adcs-certutil") {
		t.Fatalf("read before the relay advertises certutil = %d %s; want 409 naming --adcs-certutil", code, body)
	}
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "a162", Status: "active",
		Executors: &transport.ExecutorReport{Version: "a162", Kinds: []transport.ExecutorKind{{Kind: relay.KindADCSDatabase}}}}); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]map[string]any{
		"option-shaped CA": {"ca_config": "-delete", "relay_agent_id": relayID},
		"CA without host":  {"ca_config": "CORP-CA", "relay_agent_id": relayID},
		"no relay":         {"ca_config": caConfig, "relay_agent_id": ""},
	} {
		if code, body := secretsReq(t, h.servedHarness, http.MethodPost, "/api/v1/adcs/ca-database/collect", token, bad); code != http.StatusBadRequest {
			t.Errorf("%s = %d %s; want 400", name, code, body)
		}
	}

	previous := relay.CertutilPath
	t.Cleanup(func() { relay.CertutilPath = previous })
	relay.CertutilPath = writeCertutilStandIn(t, t.TempDir(), caConfig, false)

	code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/adcs/ca-database/collect", token, "a162-read-1", request)
	var queued struct {
		CollectionID string `json:"collection_id"`
		Status       string `json:"status"`
	}
	if code != http.StatusAccepted || json.Unmarshal(body, &queued) != nil || queued.Status != "queued" || queued.CollectionID == "" {
		t.Fatalf("collect = %d %s", code, body)
	}
	if code, replay := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/adcs/ca-database/collect", token, "a162-read-1", request); code != http.StatusAccepted || string(replay) != string(body) {
		t.Fatalf("replayed collect = %d %s; want the same queued read", code, replay)
	}
	if code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/adcs/ca-database/collect", token, "a162-read-2", request); code != http.StatusConflict {
		t.Fatalf("a second read while one waits = %d %s; want 409", code, body)
	}
	if got := readADCSDatabases(t, h, token, caConfig); len(got.Collections) != 1 || got.Collections[0].Status != "queued" || got.Collections[0].RelayAgentID != relayID {
		t.Fatalf("collections before the relay runs = %+v", got.Collections)
	}

	channel := &sshCollectionServedChannel{t: t, h: h}
	if count, err := relay.RunOnce(ctx, channel, http.DefaultClient, 1, 120); err != nil || count != 1 || len(channel.reports) != 1 {
		t.Fatalf("production relay = %d %v reports %d", count, err, len(channel.reports))
	}
	for _, leaked := range []string{"web01", "svc-web", "alice", "LAPTOP-9", "1a00000002"} {
		if strings.Contains(channel.reports[0].Detail, leaked) {
			t.Fatalf("the relay report carries %q from a database row: %s", leaked, channel.reports[0].Detail)
		}
	}
	got := readADCSDatabases(t, h, token, caConfig)
	if len(got.Items) != 1 {
		t.Fatalf("summaries = %+v", got.Items)
	}
	item := got.Items[0]
	if item.CAConfig != caConfig || item.Issued != 2 || item.Pending != 1 || item.Revoked != 1 || item.Unparsed != 1 ||
		item.Total != 4 || item.RowsRead != 5 || item.RowsRejected != 1 || item.Source != "relay:"+relayID {
		t.Fatalf("recorded summary = %+v", item)
	}
	if len(got.Collections) != 1 || got.Collections[0].Status != "collected" || got.Collections[0].CompletedAt == "" {
		t.Fatalf("collections after the read = %+v", got.Collections)
	}

	// A read that fails on the relay is answered with its reason, not retried,
	// and does not turn the CA's counts into an empty CA.
	relay.CertutilPath = writeCertutilStandIn(t, t.TempDir(), caConfig, true)
	if code, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/adcs/ca-database/collect", token, "a162-read-3", request); code != http.StatusAccepted {
		t.Fatalf("second collect = %d %s", code, body)
	}
	if count, err := relay.RunOnce(ctx, channel, http.DefaultClient, 1, 120); err != nil || count != 0 || len(channel.reports) != 2 {
		t.Fatalf("failing relay read = %d %v reports %d", count, err, len(channel.reports))
	}
	got = readADCSDatabases(t, h, token, caConfig)
	if len(got.Collections) != 2 || got.Collections[0].Status != "failed" || !strings.Contains(got.Collections[0].LastError, "certutil could not read") {
		t.Fatalf("collections after a failed read = %+v", got.Collections)
	}
	if len(got.Items) != 1 || got.Items[0].Issued != 2 || got.Items[0].Total != 4 {
		t.Fatalf("a failed read changed the recorded counts: %+v", got.Items)
	}
	if count, err := relay.RunOnce(ctx, channel, http.DefaultClient, 1, 120); err != nil || count != 0 || len(channel.reports) != 2 {
		t.Fatalf("the failed read was handed out again: %d %v reports %d", count, err, len(channel.reports))
	}
}
