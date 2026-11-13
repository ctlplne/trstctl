// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
)

// scimWritebackBearer is a directory's outbound SCIM bearer (A73), kept in
// locked memory and reloaded when the operator rotates its file (A207-L1):
// a writeback checks the file at most every scimTokenRecheck, and a changed
// file with a token in it replaces the bearer; an unreadable or empty
// rewrite keeps the loaded one, so a half-written rotation never leaves the
// directory without a bearer. A request holds the bearer while it uses it,
// so a reload never wipes bytes in use.
type scimWritebackBearer struct {
	path string // empty: a fixed bearer that never reloads
	now  func() time.Time

	mu   sync.RWMutex
	buf  *secret.Buffer
	stat os.FileInfo

	reload  sync.Mutex
	checked time.Time
}

// newSCIMWritebackBearer loads the bearer from path.
func newSCIMWritebackBearer(path string) (*scimWritebackBearer, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	buf, err := loadSCIMWritebackBearer(path)
	if err != nil {
		return nil, err
	}
	b := &scimWritebackBearer{path: path, now: time.Now, buf: buf, stat: info}
	b.checked = b.now()
	return b, nil
}

// fixedSCIMWritebackBearer wraps a bearer that has no file to reload.
func fixedSCIMWritebackBearer(buf *secret.Buffer) *scimWritebackBearer {
	return &scimWritebackBearer{now: time.Now, buf: buf}
}

var errSCIMWritebackBearerEmpty = errors.New("is empty")

func loadSCIMWritebackBearer(path string) (*secret.Buffer, error) {
	raw, err := secretfile.Load(path)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(raw)
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errSCIMWritebackBearerEmpty
	}
	return secret.NewFrom(trimmed)
}

// use calls fn with the current bearer, after reloading a rotated file.
func (b *scimWritebackBearer) use(fn func(bearer []byte) error) error {
	b.refresh()
	b.mu.RLock()
	defer b.mu.RUnlock()
	return fn(b.buf.Bytes())
}

func (b *scimWritebackBearer) refresh() {
	if b.path == "" || !b.reload.TryLock() {
		return // another writeback is reloading; this one uses the current bearer
	}
	defer b.reload.Unlock()
	now := b.now()
	if now.Sub(b.checked) < scimTokenRecheck {
		return
	}
	b.checked = now
	info, err := os.Stat(b.path)
	if err != nil {
		slog.Default().Warn("scim writeback token file unreadable; keeping the loaded bearer", slog.String("error", err.Error()))
		return
	}
	b.mu.RLock()
	same := sameSCIMTokenFile(b.stat, info)
	b.mu.RUnlock()
	if same {
		return
	}
	next, err := loadSCIMWritebackBearer(b.path)
	if err != nil {
		slog.Default().Warn("scim writeback bearer reload refused; keeping the loaded bearer", slog.String("error", err.Error()))
		return
	}
	b.mu.Lock()
	old := b.buf
	b.buf, b.stat = next, info
	b.mu.Unlock()
	old.Destroy()
	slog.Default().Info("scim writeback bearer reloaded")
}

// destroy wipes the bearer.
func (b *scimWritebackBearer) destroy() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Destroy()
}
