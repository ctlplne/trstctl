// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// TestServedRecordingSearchIsScopedMaskedAndAuditedA275: an auditor with
// recordings:read searches every recorded session of the tenant at once —
// a PostgreSQL statement and an SSH command's terminal output — and finds
// the text in both, each hit naming its session and target; the requester
// without recordings:read is refused and another tenant's auditor finds
// nothing. A token-shaped secret the session used is masked in the
// recording, so searching for it finds nothing and the masked form shows
// only its mask; the typed-input stream is not searched. Every search is
// recorded, its query masked.
func TestServedRecordingSearchIsScopedMaskedAndAuditedA275(t *testing.T) {
	f := startGatewayFixture(t, gatewayFixtureOptions{})
	h := f.h
	const needle, secret = "needle-a275-search", "AKIAABCDEFGHIJKLMNOP"
	await := func(id string) {
		t.Helper()
		_, _ = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+id+"/revoke", f.requester, "a275-search-revoke-"+id, map[string]any{"reason": "A275 search proof"})
		a201Await(t, "the session's recording is sealed", func() bool {
			work, cancel := context.WithTimeout(f.ctx, 20*time.Second)
			defer cancel()
			_ = h.srv.Drain(work)
			status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+id+"/recording", f.auditor, nil)
			return status == http.StatusOK && strings.Contains(string(body), `"status":"sealed"`)
		})
	}

	pgSession := f.open("a275-search-pg", map[string]any{"target_type": "postgres", "target_id": "pg-gw", "role": "readonly", "ttl_seconds": 60})
	local, stop := f.postgresTunnel(pgSession)
	conn, err := pgconn.Connect(f.ctx, "postgres://client@"+local+"/postgres?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(f.ctx, "SELECT '"+needle+"-sql' AS marker, '"+secret+"' AS key").ReadAll(); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close(context.Background())
	stop()
	await(pgSession.ID)

	sshSession := f.open("a275-search-ssh", map[string]any{"target_type": "ssh", "target_id": "ssh-gw", "role": "user", "ssh_principal": "alice", "ttl_seconds": 60})
	command, stopSSH := f.sshTunnel(sshSession)
	if out, err := command("echo", needle+"-ssh").CombinedOutput(); err != nil || !strings.Contains(string(out), needle+"-ssh") {
		t.Fatalf("ssh echo: %v %s", err, out)
	}
	stopSSH()
	await(sshSession.ID)

	search := func(token, q string) (int, api.PAMRecordingSearchResult) {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/recordings/search?q="+url.QueryEscape(q), token, nil)
		var out api.PAMRecordingSearchResult
		if status == http.StatusOK && json.Unmarshal(body, &out) != nil {
			t.Fatalf("search %q: %s", q, body)
		}
		if strings.Contains(string(body), secret) {
			t.Fatalf("the secret reached a search result: %s", body)
		}
		return status, out
	}
	status, found := search(f.auditor, needle)
	sessions := map[string]api.PAMRecordingSearchHit{}
	for _, hit := range found.Items {
		sessions[hit.SessionID+"|"+hit.Source] = hit
	}
	sqlHit, okSQL := sessions[pgSession.ID+"|sql"]
	outHit, okOut := sessions[sshSession.ID+"|output"]
	if status != http.StatusOK || !okSQL || !okOut || found.SessionsSearched < 2 || sqlHit.TargetType != "postgres" || sqlHit.TargetID != "pg-gw" ||
		!strings.Contains(sqlHit.Text, needle+"-sql") || outHit.TargetType != "ssh" || !strings.Contains(outHit.Text, needle+"-ssh") {
		t.Fatalf("search across sessions = %d %+v", status, found)
	}
	if _, cmd := sessions[sshSession.ID+"|command"]; !cmd {
		t.Fatalf("the SSH exec command was not found: %+v", found.Items)
	}

	// Masked: the secret itself finds nothing; its mask shows only the mask.
	if status, none := search(f.auditor, secret); status != http.StatusOK || len(none.Items) != 0 {
		t.Fatalf("searching for the masked secret = %d %+v", status, none)
	}
	if status, masked := search(f.auditor, "masked:aws-access-key-id"); status != http.StatusOK || len(masked.Items) == 0 ||
		!strings.Contains(masked.Items[0].Text, "[masked:aws-access-key-id]") {
		t.Fatalf("the masked line = %d %+v", status, masked)
	}

	// Scoped: no recordings:read, another tenant, a bad query.
	if status, _ := search(f.requester, needle); status != http.StatusForbidden {
		t.Fatalf("a searcher without recordings:read = %d", status)
	}
	other := uuid.NewString()
	registerServedTenantID(t, h.servedHarness, other, "A275 search isolation")
	otherAuditor := seedScopedTokenSubject(t, h.store, other, "a275-other-auditor", "recordings:read")
	if status, theirs := search(otherAuditor, needle); status != http.StatusOK || len(theirs.Items) != 0 || theirs.SessionsSearched != 0 {
		t.Fatalf("another tenant's search = %d %+v", status, theirs)
	}
	if status, _ := search(f.auditor, "ab"); status != http.StatusBadRequest {
		t.Fatalf("a two-character query = %d", status)
	}

	// Audited: every search, with its query masked.
	var searches []projections.PAMRecordingSearched
	if err := h.log.Replay(context.Background(), 0, func(e events.Event) error {
		if e.Type == projections.EventPAMRecordingSearched && e.TenantID == h.tenant {
			var pl projections.PAMRecordingSearched
			if err := json.Unmarshal(e.Data, &pl); err != nil {
				return err
			}
			searches = append(searches, pl)
			if strings.Contains(string(e.Data), secret) {
				t.Fatalf("a recorded search holds the secret: %s", e.Data)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(searches) != 3 || searches[0].Actor != "pam-auditor" || searches[0].Query != needle || searches[0].Matches != len(found.Items) ||
		len(searches[0].MatchedSessions) != 2 || searches[1].Query != "[masked:aws-access-key-id]" {
		t.Fatalf("recorded searches = %+v", searches)
	}
}
