// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// recordingOutput is what a page of frames shows: the bytes the client saw.
func recordingOutput(t *testing.T, frames []json.RawMessage) string {
	t.Helper()
	var out strings.Builder
	for _, raw := range frames {
		var f struct {
			Stream string `json:"s"`
			Data   string `json:"d"`
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			t.Fatalf("frame %s: %v", raw, err)
		}
		if f.Stream == "out" {
			b, _ := base64.StdEncoding.DecodeString(f.Data)
			out.Write(b)
		}
	}
	return out.String()
}

// TestServedRecordingPlaybackWatchExportRetentionA255: an auditor with
// recordings:read watches a live session as it happens and plays it back; with
// recordings:export exports it with the manifest the audit key signed; every
// read is recorded; the requester, without those scopes, reads nothing.
// Retention deletes a sealed recording's objects; a legal hold keeps one past
// it until the hold is released.
func TestServedRecordingPlaybackWatchExportRetentionA255(t *testing.T) {
	const retention = 20 * time.Second
	f := startGatewayFixture(t, gatewayFixtureOptions{recordingRetention: retention})
	h := f.h

	type page struct {
		Status string            `json:"status"`
		Next   int               `json:"next"`
		Frames []json.RawMessage `json:"frames"`
	}
	read := func(token, id string, from, wait int) (int, page) {
		t.Helper()
		status, body := secretsReq(t, h.servedHarness, http.MethodGet,
			"/api/v1/access/sessions/"+id+"/recording/frames?from="+strconv.Itoa(from)+"&wait="+strconv.Itoa(wait), token, nil)
		var p page
		if status == http.StatusOK {
			if err := json.Unmarshal(body, &p); err != nil {
				t.Fatal(err)
			}
		}
		return status, p
	}

	// A live session, watched as it happens.
	held := f.openSSH("a255-play-held", 120)
	command, stop := f.sshTunnel(held)
	defer stop()
	shell := startLiveShell(t, command(liveShellScript))
	shell.echo("first")
	if status, _ := read(f.requester, held.ID, 0, 0); status != http.StatusForbidden {
		t.Fatalf("the requester read a recording: %d", status)
	}
	seen := ""
	next := 0
	a201Await(t, "the watcher sees the first answer", func() bool {
		status, p := read(f.auditor, held.ID, next, 5)
		if status != http.StatusOK {
			t.Fatalf("watch = %d", status)
		}
		seen += recordingOutput(t, p.Frames)
		next = p.Next
		return strings.Contains(seen, "got first")
	})
	watched := make(chan string, 1)
	go func() {
		// A long poll that starts before the session writes anything more.
		_, p := read(f.auditor, held.ID, next, 25)
		watched <- recordingOutput(t, p.Frames)
	}()
	time.Sleep(500 * time.Millisecond)
	shell.echo("second")
	select {
	case got := <-watched:
		if !strings.Contains(got, "got second") {
			t.Fatalf("the live watch returned %q", got)
		}
	case <-time.After(40 * time.Second):
		t.Fatal("the live watch did not return the session's new output")
	}

	// The session ends; its recording seals and exports with a signed
	// manifest.
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+held.ID+"/terminate", f.operator,
		"a255-play-held-terminate", map[string]any{"reason": "playback proof"}); status != http.StatusAccepted {
		t.Fatalf("terminate = %d", status)
	}
	sealed := func(id string) bool {
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+id+"/recording", f.requester, nil)
		return status == http.StatusOK && strings.Contains(string(body), `"status":"sealed"`)
	}
	a201Await(t, "the watched recording seals", func() bool { return sealed(held.ID) })
	if status, _ := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+held.ID+"/recording/export", f.requester, nil); status != http.StatusForbidden {
		t.Fatalf("the requester exported a recording: %d", status)
	}
	status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+held.ID+"/recording/export", f.auditor, nil)
	if status != http.StatusOK {
		t.Fatalf("export = %d %s", status, body)
	}
	var export struct {
		Manifest          json.RawMessage   `json:"manifest"`
		ManifestSignature string            `json:"manifest_signature"`
		Frames            []json.RawMessage `json:"frames"`
	}
	if err := json.Unmarshal(body, &export); err != nil {
		t.Fatal(err)
	}
	signed, err := f.auditKey.JWKS().VerifyArtifact(export.ManifestSignature, recordingManifestArtifact)
	if err != nil || !bytes.Equal(bytes.TrimSpace(signed), bytes.TrimSpace(export.Manifest)) {
		t.Fatalf("the exported manifest is not the one the audit key signed: %v", err)
	}
	if out := recordingOutput(t, export.Frames); !strings.Contains(out, "got first") || !strings.Contains(out, "got second") {
		t.Fatalf("the export holds %q", out)
	}
	reads := 0
	if err := h.log.Replay(context.Background(), 0, func(e events.Event) error {
		if e.Type == projections.EventPAMRecordingRead && e.TenantID == h.tenant && strings.Contains(string(e.Data), `"actor":"pam-auditor"`) {
			reads++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if reads < 3 {
		t.Fatalf("%d recording reads were recorded, want every one", reads)
	}

	// A legal hold keeps the exported recording past retention.
	status, body = secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+held.ID+"/recording/legal-hold", f.auditor,
		"a255-hold", map[string]any{"reason": "litigation hold 7"})
	if status != http.StatusOK || !strings.Contains(string(body), `"legal_hold":true`) {
		t.Fatalf("place hold = %d %s", status, body)
	}
	// A second session, unheld.
	loose := f.openSSH("a255-play-loose", 120)
	looseCommand, stopLoose := f.sshTunnel(loose)
	defer stopLoose()
	if out, err := looseCommand("echo loose").CombinedOutput(); err != nil || !strings.Contains(string(out), "loose") {
		t.Fatalf("ssh = %q %v", out, err)
	}
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+loose.ID+"/terminate", f.operator,
		"a255-play-loose-terminate", map[string]any{"reason": "retention proof"}); status != http.StatusAccepted {
		t.Fatalf("terminate = %d", status)
	}
	a201Await(t, "the unheld recording seals", func() bool { return sealed(loose.ID) })
	objectsOf := func(id string) int {
		n := 0
		for _, key := range f.objects.Keys() {
			if strings.Contains(key, "recordings/"+id+"/") {
				n++
			}
		}
		return n
	}
	if objectsOf(loose.ID) == 0 || objectsOf(held.ID) == 0 {
		t.Fatal("sealed recordings have no objects")
	}
	deleted := func(id string) bool {
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+id+"/recording", f.requester, nil)
		return status == http.StatusOK && strings.Contains(string(body), `"status":"deleted"`)
	}
	a201Await(t, "retention deletes the unheld recording", func() bool { return deleted(loose.ID) })
	if objectsOf(loose.ID) != 0 {
		t.Fatal("retention left the unheld recording's objects")
	}
	if status, _ := read(f.auditor, loose.ID, 0, 0); status != http.StatusConflict {
		t.Fatalf("a deleted recording was played back: %d", status)
	}
	time.Sleep(time.Second)
	if deleted(held.ID) || objectsOf(held.ID) == 0 {
		t.Fatal("retention deleted a recording on legal hold")
	}
	if status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+held.ID+"/recording/verify", f.requester, nil); status != http.StatusOK || !strings.Contains(string(body), `"verified":true`) {
		t.Fatalf("the held recording no longer verifies: %d %s", status, body)
	}
	// Released, it is deleted on the next pass.
	status, body = secretsReqKey(t, h.servedHarness, http.MethodDelete, "/api/v1/access/sessions/"+held.ID+"/recording/legal-hold", f.auditor, "a255-release", nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"legal_hold":false`) {
		t.Fatalf("release hold = %d %s", status, body)
	}
	a201Await(t, "retention deletes the released recording", func() bool { return deleted(held.ID) && objectsOf(held.ID) == 0 })
}
