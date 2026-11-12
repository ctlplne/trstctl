// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/store"
)

// Q6-O1: a host agent registers the decoy files it planted over its channel
// and reports each open; the control plane alerts once per opening program,
// naming it and the host, keeps the first opener on the decoy, lists the
// decoys to those who may plant them (never in the host inventory) and stops
// alerting on a retired decoy. Only a host agent's reports are taken, and only
// for its own host.
func TestServedDecoyFileOpensAlertOncePerProgramQ6O1(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleHost}, nil, withIsolatedTenant)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "decoy-test", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	private, public, err := crypto.GenerateSSHClientKey("backup@decoy-host")
	if err != nil {
		t.Fatal(err)
	}
	secret.Wipe(private)
	const decoyPath = "/root/.ssh/id_ed25519_backup"
	report := func(req *transport.DecoyReportRequest) *transport.DecoyReportResponse {
		t.Helper()
		resp, err := h.client.ReportDecoys(ctx, req)
		if err != nil {
			t.Fatalf("report decoys: %v", err)
		}
		return resp
	}
	registered := report(&transport.DecoyReportRequest{Decoys: []transport.DecoyFile{{Path: decoyPath, PublicKey: string(public), PlantedAt: time.Now().UTC()}}})
	if registered.Registered != 1 || registered.Known != 0 || registered.TenantID != h.tenant {
		t.Fatalf("registration = %+v, want one new decoy in %s", registered, h.tenant)
	}
	if again := report(&transport.DecoyReportRequest{Decoys: []transport.DecoyFile{{Path: decoyPath, PublicKey: string(public), PlantedAt: time.Now().UTC()}}}); again.Registered != 0 || again.Known != 1 {
		t.Fatalf("a restarted agent's registration = %+v, want the same decoy known", again)
	}
	alerts := func() []map[string]any {
		t.Helper()
		rows, err := h.store.SystemPool().Query(ctx,
			`SELECT payload FROM outbox WHERE tenant_id = $1 AND destination = 'notification.honeytoken' ORDER BY id`, h.tenant)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []map[string]any
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var alert map[string]any
			if err := json.Unmarshal(raw, &alert); err != nil {
				t.Fatal(err)
			}
			out = append(out, alert)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := alerts(); len(got) != 0 {
		t.Fatalf("planting raised %d alerts", len(got))
	}

	now := time.Now().UTC()
	opened := report(&transport.DecoyReportRequest{Opens: []transport.DecoyOpen{
		{Path: decoyPath, At: now, PID: 4242, Process: "cat (/bin/busybox)", Mechanism: "fanotify"},
		{Path: decoyPath, At: now.Add(time.Second), PID: 4243, Process: "cat (/bin/busybox)", Mechanism: "fanotify"},
		{Path: "/home/app/.ssh/id_rsa", At: now, PID: 4244, Process: "cat (/bin/busybox)", Mechanism: "fanotify"},
	}})
	if opened.Recorded != 2 || opened.Rejected != 1 {
		t.Fatalf("opens = %+v, want two recorded and the open of a path with no decoy refused", opened)
	}
	got := alerts()
	if len(got) != 1 {
		t.Fatalf("%d alerts after two opens by one program, want 1: %v", len(got), got)
	}
	detail, _ := got[0]["detail"].(string)
	for _, want := range []string{decoyPath, "on " + h.agent, "cat (/bin/busybox) on " + h.agent, "pid 4242", "fanotify"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("alert detail %q does not name %q", detail, want)
		}
	}
	if got[0]["severity"] != "critical" || got[0]["kind"] != "honeytoken.triggered" {
		t.Fatalf("alert = %v, want a critical honeytoken.triggered", got[0])
	}
	report(&transport.DecoyReportRequest{Opens: []transport.DecoyOpen{
		{Path: decoyPath, At: now.Add(2 * time.Second), PID: 4250, Process: "scp", Mechanism: "fanotify"},
	}})
	if got := alerts(); len(got) != 2 || !strings.Contains(got[1]["detail"].(string), "scp on "+h.agent) {
		t.Fatalf("alerts after a second program opened the decoy = %v, want a second naming scp", got)
	}

	operator := seedServedAPIToken(t, ctx, h.store, h.tenant, "decoy-planter", []string{"secrets:write", "secrets:read"})
	reader := seedServedAPIToken(t, ctx, h.store, h.tenant, "secret-reader", []string{"secrets:read"})
	if code, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/secrets/honeytokens/files", reader, "", nil); code != http.StatusForbidden {
		t.Fatalf("a reader who may not plant decoys listed them: %d %s", code, body)
	}
	code, body := doBearer(t, h.ts, http.MethodGet, "/api/v1/secrets/honeytokens/files", operator, "", nil)
	if code != http.StatusOK {
		t.Fatalf("list decoy files: %d %s", code, body)
	}
	var list struct {
		Items []store.HoneyToken `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil || len(list.Items) != 1 {
		t.Fatalf("decoy files = %s (%v), want one", body, err)
	}
	listed := list.Items[0]
	if listed.Kind != "file" || listed.FileHost != h.agent || listed.FilePath != decoyPath ||
		!strings.HasPrefix(listed.FileKeyFingerprint, "SHA256:") || listed.State != "triggered" ||
		listed.TriggerSubject != "cat (/bin/busybox) on "+h.agent || listed.TriggerMethod != "open, pid 4242, seen by fanotify" ||
		listed.Readers != 2 || listed.Reads != 3 {
		t.Fatalf("listed decoy = %+v", listed)
	}
	if strings.Contains(string(body), "PRIVATE KEY") {
		t.Fatal("the decoy list carries private key material")
	}
	var findings int
	if err := h.store.SystemPool().QueryRow(ctx,
		`SELECT count(*) FROM discovery_findings WHERE tenant_id = $1 AND (ref LIKE '%id_ed25519_backup%' OR kind LIKE 'decoy%')`, h.tenant).Scan(&findings); err != nil {
		t.Fatal(err)
	}
	if findings != 0 {
		t.Fatalf("%d host inventory findings name the decoy", findings)
	}

	code, body = doBearer(t, h.ts, http.MethodPost, "/api/v1/secrets/honeytokens/files/"+listed.ID+"/retire", operator, "retire-decoy-file", nil)
	if code != http.StatusOK || !strings.Contains(string(body), `"state":"revoked"`) {
		t.Fatalf("retire decoy file: %d %s", code, body)
	}
	if after := report(&transport.DecoyReportRequest{Opens: []transport.DecoyOpen{
		{Path: decoyPath, At: time.Now().UTC(), PID: 4260, Process: "rsync", Mechanism: "inotify"},
	}}); after.Recorded != 0 || after.Rejected != 1 {
		t.Fatalf("an open of a retired decoy = %+v, want refused", after)
	}
	if again := report(&transport.DecoyReportRequest{Decoys: []transport.DecoyFile{{Path: decoyPath, PublicKey: string(public), PlantedAt: time.Now().UTC()}}}); again.Known != 1 {
		t.Fatalf("the agent re-reporting a retired decoy = %+v, want it known and left retired", again)
	}
	if got := alerts(); len(got) != 2 {
		t.Fatalf("%d alerts after the decoy was retired, want 2", len(got))
	}

	for name, req := range map[string]*transport.DecoyReportRequest{
		"relative path":   {Decoys: []transport.DecoyFile{{Path: "id_ed25519", PublicKey: string(public)}}},
		"not a key":       {Decoys: []transport.DecoyFile{{Path: "/srv/id_ed25519", PublicKey: "-----BEGIN OPENSSH PRIVATE KEY-----"}}},
		"unclean path":    {Opens: []transport.DecoyOpen{{Path: "/root/../root/.ssh/id_ed25519_backup", At: now}}},
		"control char":    {Opens: []transport.DecoyOpen{{Path: decoyPath, At: now, Process: "cat\x1b[2J"}}},
		"empty report":    {},
		"unknown watcher": {Opens: []transport.DecoyOpen{{Path: decoyPath, At: now, Mechanism: "auditd"}}},
	} {
		if _, err := h.client.ReportDecoys(ctx, req); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("%s: err = %v, want InvalidArgument", name, err)
		}
	}

	network := newRoleHarnessNamedWithEventOptions(t, "decoy-network-agent", []string{mtls.AgentRoleNetwork}, nil, nil)
	if _, err := network.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: network.agent, Version: "decoy-test", Status: "active"}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if _, err := network.client.ReportDecoys(ctx, &transport.DecoyReportRequest{Decoys: []transport.DecoyFile{{Path: decoyPath, PublicKey: string(public)}}}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a network agent's decoy report: %v, want PermissionDenied", err)
	}
}
