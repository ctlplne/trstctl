// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestServedRecordingRetentionRemovesEveryVersionA206L2L1 (served, a gateway
// session recorded into an archive that keeps object versions, as a bucket
// with S3 versioning or Object Lock does): retention removes every version
// of the recording's chunks and manifest, leaving no delete marker and none
// of the sealed data behind one, where a plain delete would leave all of it.
// While an S3 Object Lock protects one chunk the recording stays whole (no
// object removed, no marker added, not marked deleted), and the pass after
// the lock lapses removes it.
func TestServedRecordingRetentionRemovesEveryVersionA206L2L1(t *testing.T) {
	const retention = 3 * time.Second
	f := startGatewayFixture(t, gatewayFixtureOptions{recordingRetention: retention, versionedObjects: true})
	h := f.h
	session := f.openSSH("a206l2l1-session", 120)
	command, stop := f.sshTunnel(session)
	if out, err := command("echo kept-in-versions").CombinedOutput(); err != nil || !strings.Contains(string(out), "kept-in-versions") {
		t.Fatalf("ssh = %q %v", out, err)
	}
	stop()
	if status, _ := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/terminate", f.operator,
		"a206l2l1-terminate", map[string]any{"reason": "version retention proof"}); status != http.StatusAccepted {
		t.Fatalf("terminate = %d", status)
	}
	recording := func() string {
		_, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording", f.requester, nil)
		return string(body)
	}
	a201Await(t, "the recording seals", func() bool { return strings.Contains(recording(), `"status":"sealed"`) })
	objects := func() map[string]int {
		out := map[string]int{}
		for _, name := range f.versioned.Names() {
			if strings.Contains(name, "recordings/"+session.ID+"/") {
				out[name] = f.versioned.VersionCount(name)
			}
		}
		return out
	}
	sealedObjects := objects()
	var chunk string
	for name, versions := range sealedObjects {
		if versions != 1 {
			t.Fatalf("%s has %d versions after sealing, want 1", name, versions)
		}
		if !strings.HasSuffix(name, "manifest.json") && chunk == "" {
			chunk = name
		}
	}
	if len(sealedObjects) < 2 || chunk == "" {
		t.Fatalf("the sealed recording's objects = %v, want chunks and a manifest", sealedObjects)
	}

	// An S3 Object Lock on one chunk keeps the whole recording past retention.
	lockedUntil := time.Now().Add(retention + 4*time.Second)
	f.versioned.Retain(chunk, lockedUntil)
	time.Sleep(retention + 2*time.Second)
	if strings.Contains(recording(), `"status":"deleted"`) {
		t.Fatal("retention marked a recording deleted while Object Lock protects one of its chunks")
	}
	if now := objects(); len(now) != len(sealedObjects) {
		t.Fatalf("under Object Lock the recording's objects went from %v to %v", sealedObjects, now)
	} else {
		for name, versions := range now {
			if versions != 1 {
				t.Fatalf("under Object Lock %s has %d versions and markers, want its one version", name, versions)
			}
		}
	}

	// Once the lock lapses, a pass removes every version: nothing is left,
	// not even a delete marker.
	a201Await(t, "retention deletes the recording after the lock lapses", func() bool {
		return strings.Contains(recording(), `"status":"deleted"`)
	})
	if left := objects(); len(left) != 0 {
		t.Fatalf("versions or markers left behind: %v", left)
	}
	for _, key := range f.objects.Keys() {
		if strings.Contains(key, "recordings/"+session.ID+"/") {
			t.Fatalf("the current object %s is still in the bucket", key)
		}
	}
	t.Logf("A206L2L1_OK objects=%d locked_until=%s", len(sealedObjects), lockedUntil.UTC().Format(time.RFC3339))
}
