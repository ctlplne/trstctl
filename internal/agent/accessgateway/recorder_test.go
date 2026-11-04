// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
)

type fakeUploader struct {
	mu     sync.Mutex
	chunks [][]byte
	finals []bool
}

func (f *fakeUploader) UploadSessionRecording(_ context.Context, _ int64, _, seq int, chunk []byte, final bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if seq != len(f.chunks) {
		return relay.ErrJobClaimLost
	}
	f.chunks = append(f.chunks, append([]byte(nil), chunk...))
	f.finals = append(f.finals, final)
	return nil
}

func TestRecorderUploadsMaskedFramesInOrderA255(t *testing.T) {
	up := &fakeUploader{}
	rec := newSessionRecorder(context.Background(), up, relay.Job{JobID: 7, Attempt: 1}, time.Now, []byte("injected-Pa55word"))
	c := rec.connection()
	exec := binary.BigEndian.AppendUint32(nil, uint32(len("echo injected-Pa55word")))
	c.Request(1, "client", "exec", append(exec, "echo injected-Pa55word"...))
	c.Data(1, "out", []byte("injected-Pa"))
	c.Data(1, "out", []byte("55word\n"))
	c.Data(1, "out", []byte("token AKIA"+"IOSFODNN7EXAMPLE end\n"))
	c.Request(1, "target", "exit-status", []byte{0, 0, 0, 0})
	c.close()
	rec.close()

	if len(up.chunks) == 0 || !up.finals[len(up.finals)-1] {
		t.Fatalf("chunks %d finals %v: the recording was not closed", len(up.chunks), up.finals)
	}
	all := bytes.Join(up.chunks, nil)
	if bytes.Contains(all, []byte("Pa55word")) || bytes.Contains(all, []byte("IOSFODNN7EXAMPLE")) {
		t.Fatalf("a secret reached the recording: %s", all)
	}
	var out strings.Builder
	var kinds []string
	lines := bufio.NewScanner(bytes.NewReader(all))
	for lines.Scan() {
		var f frame
		if err := json.Unmarshal(lines.Bytes(), &f); err != nil {
			t.Fatalf("frame %q: %v", lines.Bytes(), err)
		}
		if f.Event != "" {
			kinds = append(kinds, f.Event+":"+f.Kind+":"+f.Text)
		}
		if f.Stream == "out" {
			b, _ := base64.StdEncoding.DecodeString(f.Data)
			out.Write(b)
		}
	}
	if got := out.String(); got != "[masked:session-credential]\ntoken [masked:aws-access-key-id] end\n" {
		t.Fatalf("recorded output %q", got)
	}
	want := []string{"connect::", "request:exec:echo [masked:session-credential]", "request:exit-status:0", "close::"}
	if strings.Join(kinds, "|") != strings.Join(want, "|") {
		t.Fatalf("events %v, want %v", kinds, want)
	}
}

func TestRecorderStopsWhenTheControlPlaneStopsTakingItA255(t *testing.T) {
	stopped := uploaderFunc(func(context.Context, int64, int, int, []byte, bool) error { return relay.ErrJobClaimLost })
	rec := newSessionRecorder(context.Background(), stopped, relay.Job{JobID: 7, Attempt: 1}, time.Now)
	c := rec.connection()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 40; i++ {
			c.Data(1, "out", bytes.Repeat([]byte("x"), 64<<10))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a stopped recording blocked the session")
	}
	rec.close()
}

type uploaderFunc func(context.Context, int64, int, int, []byte, bool) error

func (f uploaderFunc) UploadSessionRecording(ctx context.Context, job int64, attempt, seq int, chunk []byte, final bool) error {
	return f(ctx, job, attempt, seq, chunk, final)
}
