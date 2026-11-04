// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// RecordingUploader is the part of the agent channel that takes a held
// session's recording, chunk by chunk and in order (A255). The control plane
// seals each chunk for the tenant and chains it; the final chunk closes the
// recording and has its manifest signed.
type RecordingUploader interface {
	UploadSessionRecording(ctx context.Context, jobID int64, attempt, seq int, chunk []byte, final bool) error
}

const (
	// recordingChunk is the most one upload carries.
	recordingChunk = 256 << 10
	// recordingSpool bounds what waits for upload; a full spool blocks the
	// session's traffic until the upload catches up.
	recordingSpool = 4 << 20
	// recordingFlush paces uploads of a quiet session, for live watching.
	recordingFlush = 500 * time.Millisecond
)

// ErrRecordingStopped means the control plane takes no more of this
// session's recording (it is sealed, or the job is no longer this gateway's).
var ErrRecordingStopped = errors.New("accessgateway: the session's recording was stopped")

// frame is one line of a recording.
type frame struct {
	T       int64   `json:"t"` // milliseconds since the session's recording began
	Conn    int     `json:"c"`
	Ch      int     `json:"ch,omitempty"`
	Stream  string  `json:"s,omitempty"` // in, out, err
	Data    string  `json:"d,omitempty"` // base64 of the masked bytes
	Event   string  `json:"e,omitempty"` // request, sftp, sql, result, connect, close
	From    string  `json:"from,omitempty"`
	Kind    string  `json:"kind,omitempty"`
	Text    string  `json:"v,omitempty"`
	SFTP    *sftpOp `json:"op,omitempty"`
	Columns int     `json:"cols,omitempty"`
}

// sessionRecorder records one held session: every connection's traffic,
// masked, encoded as JSON lines, spooled under a bound and uploaded in order.
type sessionRecorder struct {
	upload  func(ctx context.Context, seq int, chunk []byte, final bool) error
	secrets [][]byte
	start   time.Time
	now     func() time.Time

	mu      sync.Mutex
	cond    *sync.Cond
	spool   bytes.Buffer
	conns   int
	closing bool
	stopped bool
	// flushDue is set every recordingFlush, so a quiet session's tail is
	// uploaded without waiting for a full chunk.
	flushDue bool
	done     chan struct{}
}

func newSessionRecorder(ctx context.Context, uploader RecordingUploader, job relay.Job, now func() time.Time, secrets ...[]byte) *sessionRecorder {
	r := &sessionRecorder{start: now(), now: now, done: make(chan struct{})}
	for _, s := range secrets {
		if len(s) > 0 {
			r.secrets = append(r.secrets, append([]byte(nil), s...))
		}
	}
	r.cond = sync.NewCond(&r.mu)
	r.upload = func(ctx context.Context, seq int, chunk []byte, final bool) error {
		return uploader.UploadSessionRecording(ctx, job.JobID, job.Attempt, seq, chunk, final)
	}
	go r.run(ctx)
	return r
}

// write appends encoded lines, waiting while the spool is full.
func (r *sessionRecorder) write(f frame) {
	f.T = r.now().Sub(r.start).Milliseconds()
	line, err := json.Marshal(f)
	if err != nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for r.spool.Len()+len(line) > recordingSpool && !r.stopped && !r.closing {
		r.cond.Wait()
	}
	if r.stopped {
		return
	}
	r.spool.Write(line)
	r.spool.WriteByte('\n')
	if r.spool.Len() >= recordingChunk {
		r.cond.Broadcast()
	}
}

func (r *sessionRecorder) isStopped() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stopped
}

// connection starts recording one admitted connection.
func (r *sessionRecorder) connection() *connRecorder {
	r.mu.Lock()
	r.conns++
	n := r.conns
	r.mu.Unlock()
	c := &connRecorder{r: r, conn: n, maskers: map[string]*masker{}, sftp: map[int]*sftpTracker{}}
	r.write(frame{Conn: n, Event: "connect"})
	return c
}

// close flushes and uploads the last chunk, marking the recording final,
// then wipes the secrets it masked.
func (r *sessionRecorder) close() {
	r.mu.Lock()
	r.closing = true
	r.cond.Broadcast()
	r.mu.Unlock()
	<-r.done
	r.wipe()
}

// abandon stops a recording that never started its session (a duplicate
// claim): nothing is uploaded.
func (r *sessionRecorder) abandon() {
	r.mu.Lock()
	r.stopped = true
	r.closing = true
	r.spool.Reset()
	r.cond.Broadcast()
	r.mu.Unlock()
	<-r.done
	r.wipe()
}

func (r *sessionRecorder) wipe() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.secrets {
		secret.Wipe(s)
	}
	r.secrets = nil
}

// run uploads the spool in order: a full chunk at once, a quiet session's
// tail every recordingFlush, the rest when closing. A transient failure
// keeps the chunk and retries; a recalled job stops the recording.
func (r *sessionRecorder) run(ctx context.Context) {
	defer close(r.done)
	seq := 0
	ticker := time.NewTicker(recordingFlush)
	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-r.done:
				return
			case <-ticker.C:
				r.mu.Lock()
				r.flushDue = true
				r.cond.Broadcast()
				r.mu.Unlock()
			}
		}
	}()
	for {
		r.mu.Lock()
		for !r.closing && r.spool.Len() < recordingChunk && (!r.flushDue || r.spool.Len() == 0) {
			r.cond.Wait()
		}
		r.flushDue = false
		if r.stopped {
			r.mu.Unlock()
			return
		}
		final := r.closing
		n := min(r.spool.Len(), recordingChunk)
		if n < r.spool.Len() {
			// End a chunk on a line.
			if cut := bytes.LastIndexByte(r.spool.Bytes()[:n], '\n'); cut >= 0 {
				n = cut + 1
			}
			final = false
		}
		chunk := append([]byte(nil), r.spool.Bytes()[:n]...)
		r.mu.Unlock()
		err := r.send(ctx, seq, chunk, final)
		r.mu.Lock()
		if err != nil {
			r.stopped = true
			r.spool.Reset()
			r.cond.Broadcast()
			r.mu.Unlock()
			return
		}
		r.spool.Next(n)
		seq++
		r.cond.Broadcast()
		r.mu.Unlock()
		if final {
			return
		}
	}
}

// send uploads one chunk, retrying transient failures with backoff until the
// control plane takes it or stops the recording.
func (r *sessionRecorder) send(ctx context.Context, seq int, chunk []byte, final bool) error {
	backoff := 200 * time.Millisecond
	for {
		err := r.upload(context.WithoutCancel(ctx), seq, chunk, final)
		if err == nil {
			return nil
		}
		if errors.Is(err, relay.ErrJobClaimLost) || errors.Is(err, ErrRecordingStopped) {
			return err
		}
		time.Sleep(backoff)
		backoff = min(backoff*2, 5*time.Second)
	}
}

// connRecorder records one connection; for SSH it is the session channels'
// recorder (sshgateway.Recorder).
type connRecorder struct {
	r       *sessionRecorder
	conn    int
	mu      sync.Mutex
	maskers map[string]*masker
	sftp    map[int]*sftpTracker
}

func (c *connRecorder) maskerFor(key string) *masker {
	m := c.maskers[key]
	if m == nil {
		m = newMasker(c.r.secrets...)
		c.maskers[key] = m
	}
	return m
}

// Data records bytes on a session channel; an SFTP channel's bytes are read
// as operations instead.
func (c *connRecorder) Data(ch int, stream string, p []byte) {
	if c.r.isStopped() {
		return
	}
	c.mu.Lock()
	if tracker := c.sftp[ch]; tracker != nil {
		switch stream {
		case "in":
			tracker.Client(p)
		case "out":
			tracker.Target(p)
		}
		c.mu.Unlock()
		return
	}
	out := c.maskerFor(strconv.Itoa(ch) + "/" + stream).Write(p)
	c.mu.Unlock()
	if len(out) > 0 {
		c.r.write(frame{Conn: c.conn, Ch: ch, Stream: stream, Data: base64.StdEncoding.EncodeToString(out)})
	}
}

// Request records a session request with its payload read as text.
func (c *connRecorder) Request(ch int, from, kind string, payload []byte) {
	text := requestText(kind, payload)
	c.mu.Lock()
	if kind == "subsystem" && text == "sftp" {
		c.sftp[ch] = newSFTPTracker(func(op sftpOp) { c.r.write(frame{Conn: c.conn, Ch: ch, Event: "sftp", SFTP: &op}) })
	}
	m := newMasker(c.r.secrets...)
	masked := string(append(m.Write([]byte(text)), m.Flush()...))
	m.Close()
	c.mu.Unlock()
	c.r.write(frame{Conn: c.conn, Ch: ch, Event: "request", From: from, Kind: kind, Text: masked})
}

// event records a structured event (database statements and results).
func (c *connRecorder) event(name, kind, text string, columns int) {
	c.mu.Lock()
	m := newMasker(c.r.secrets...)
	masked := string(append(m.Write([]byte(text)), m.Flush()...))
	m.Close()
	c.mu.Unlock()
	c.r.write(frame{Conn: c.conn, Event: name, Kind: kind, Text: masked, Columns: columns})
}

// close flushes the connection's masked tails.
func (c *connRecorder) close() {
	c.mu.Lock()
	type tail struct {
		ch     int
		stream string
		data   []byte
	}
	var tails []tail
	for key, m := range c.maskers {
		if out := m.Flush(); len(out) > 0 {
			var ch int
			stream := ""
			for i := 0; i < len(key); i++ {
				if key[i] == '/' {
					ch, _ = strconv.Atoi(key[:i])
					stream = key[i+1:]
					break
				}
			}
			tails = append(tails, tail{ch, stream, out})
		}
		m.Close()
	}
	c.maskers = map[string]*masker{}
	c.mu.Unlock()
	for _, t := range tails {
		c.r.write(frame{Conn: c.conn, Ch: t.ch, Stream: t.stream, Data: base64.StdEncoding.EncodeToString(t.data)})
	}
	c.r.write(frame{Conn: c.conn, Event: "close"})
}

// requestText reads an SSH session request's payload as text: the command
// for exec, the name for subsystem and signal, name=value for env, the
// terminal and size for pty-req and window-change, the code for exit-status.
func requestText(kind string, p []byte) string {
	str := func(b []byte) (string, []byte) {
		if len(b) < 4 {
			return "", nil
		}
		n := binary.BigEndian.Uint32(b)
		if int64(len(b)-4) < int64(n) {
			return "", nil
		}
		return string(b[4 : 4+n]), b[4+n:]
	}
	u32 := func(b []byte) (uint32, []byte) {
		if len(b) < 4 {
			return 0, nil
		}
		return binary.BigEndian.Uint32(b), b[4:]
	}
	switch kind {
	case "exec", "subsystem", "signal", "exit-signal":
		s, _ := str(p)
		return s
	case "env":
		name, rest := str(p)
		value, _ := str(rest)
		return name + "=" + value
	case "pty-req":
		term, rest := str(p)
		cols, rest := u32(rest)
		rows, _ := u32(rest)
		return term + " " + strconv.FormatUint(uint64(cols), 10) + "x" + strconv.FormatUint(uint64(rows), 10)
	case "window-change":
		cols, rest := u32(p)
		rows, _ := u32(rest)
		return strconv.FormatUint(uint64(cols), 10) + "x" + strconv.FormatUint(uint64(rows), 10)
	case "exit-status":
		code, _ := u32(p)
		return strconv.FormatUint(uint64(code), 10)
	}
	return ""
}
