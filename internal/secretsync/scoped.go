// SPDX-License-Identifier: BUSL-1.1

package secretsync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// ScopedTarget is a destination whose keys a scoped sync (A237) can list, read
// back and delete. Values never leave it: ReadDigest returns the SHA-256 of the
// stored value, the digest a sync job records for the value it delivered.
type ScopedTarget interface {
	ListKeys(ctx context.Context, prefix string, limit int) ([]string, error)
	ReadDigest(ctx context.Context, key string) (exists bool, digest string, err error)
	Delete(ctx context.Context, key string) error
}

// A scoped destination may also answer how it names keys and what it reads
// back (A241). Without these answers it holds paths and reads values.
type (
	scopedKeyRules interface {
		FlatKeys() bool
		ValidKey(key string) error
	}
	scopedReadBack interface {
		ReadsBack() bool
		DigestOf(value []byte) string
	}
)

// ScopedFlatKeys reports whether t holds variable names, not paths: a scoped
// sync's destination prefix is then a name prefix, joined without a slash.
func ScopedFlatKeys(t ScopedTarget) bool {
	rules, ok := t.(scopedKeyRules)
	return ok && rules.FlatKeys()
}

// ScopedValidKey reports whether t can hold key.
func ScopedValidKey(t ScopedTarget, key string) error {
	if rules, ok := t.(scopedKeyRules); ok {
		return rules.ValidKey(key)
	}
	return nil
}

// ScopedReadsBack reports whether t's stored values can be compared; false is
// a receipt-only destination.
func ScopedReadsBack(t ScopedTarget) bool {
	if rb, ok := t.(scopedReadBack); ok {
		return rb.ReadsBack()
	}
	return true
}

// ScopedDigestOf is the digest ReadDigest returns when t holds value.
func ScopedDigestOf(t ScopedTarget, value []byte) string {
	if rb, ok := t.(scopedReadBack); ok {
		return rb.DigestOf(value)
	}
	return crypto.SHA256Hex(value)
}

// ErrScopedListLimit is a destination holding more keys under a prefix than a
// plan reads; the operator narrows the scope.
var ErrScopedListLimit = errors.New("secretsync: the destination holds more keys under the prefix than a plan reads")

// Scoped returns the target's scoped operations when its destination exposes
// its keys. A pusher may implement the methods but decline by type.
func (t *Target) Scoped() (ScopedTarget, bool) {
	scoped, ok := t.pusher.(ScopedTarget)
	if !ok {
		return nil, false
	}
	if gate, gated := t.pusher.(interface{ ScopedKeys() bool }); gated && !gate.ScopedKeys() {
		return nil, false
	}
	return scoped, true
}

// ListKeys walks the KV v2 metadata tree under prefix (relative to the
// target's path prefix) and returns every secret path, in order. A path can be
// both a secret and a folder ("db" and "db/password"); both are returned.
func (p *VaultKVV2Pusher) ListKeys(ctx context.Context, prefix string, limit int) ([]string, error) {
	root, err := normalizedVaultPath(prefix, true)
	if err != nil {
		return nil, fmt.Errorf("secretsync: Vault KV v2 list prefix: %w", err)
	}
	var out []string
	queue := []string{root}
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		entries, err := p.listOnce(ctx, dir)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			name := strings.TrimSuffix(entry, "/")
			if name == "" || strings.Contains(name, "/") {
				return nil, errors.New("secretsync: Vault KV v2 list returned an invalid entry")
			}
			full := name
			if dir != "" {
				full = dir + "/" + name
			}
			if strings.HasSuffix(entry, "/") {
				queue = append(queue, full)
				continue
			}
			if out = append(out, full); len(out) > limit {
				return nil, ErrScopedListLimit
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

func (p *VaultKVV2Pusher) listOnce(ctx context.Context, dir string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint+p.metadataPath(dir)+"?list=true", nil)
	if err != nil {
		return nil, err
	}
	p.authorize(req)
	var response struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	err = readJSON2xx(p.doer, req, &response)
	if statusCode(err) == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("secretsync: list Vault KV v2 metadata: %w", err)
	}
	return response.Data.Keys, nil
}

// ReadDigest reads one path and returns whether it exists and the SHA-256 of
// this target's field ("" when the path exists without that field or holds a
// non-string value). The value is wiped before it returns.
func (p *VaultKVV2Pusher) ReadDigest(ctx context.Context, key string) (bool, string, error) {
	path, err := normalizedVaultPath(key, false)
	if err != nil {
		return false, "", fmt.Errorf("secretsync: Vault KV v2 key: %w", err)
	}
	state, err := p.read(ctx, path)
	if err != nil {
		return false, "", err
	}
	defer state.wipe()
	if state.version == 0 {
		return false, "", nil
	}
	raw, ok := state.data[p.field]
	if !ok {
		return true, "", nil
	}
	var current secret.JSONBytes
	if err := json.Unmarshal(raw, &current); err != nil {
		return true, "", nil
	}
	defer secret.Wipe(current)
	return true, crypto.SHA256Hex(current), nil
}

// Delete removes a path and every version of it (KV v2 metadata delete). A
// path that is already gone is not an error, so a retried delete is safe.
func (p *VaultKVV2Pusher) Delete(ctx context.Context, key string) error {
	path, err := normalizedVaultPath(key, false)
	if err != nil {
		return fmt.Errorf("secretsync: Vault KV v2 key: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, p.endpoint+p.metadataPath(path), nil)
	if err != nil {
		return err
	}
	p.authorize(req)
	if err := expect2xx(p.doer, req); err != nil && statusCode(err) != http.StatusNotFound {
		return fmt.Errorf("secretsync: delete Vault KV v2 path: %w", err)
	}
	return nil
}

func (p *VaultKVV2Pusher) metadataPath(path string) string {
	parts := []string{"v1"}
	parts = append(parts, strings.Split(p.mount, "/")...)
	parts = append(parts, "metadata")
	if p.pathPrefix != "" {
		parts = append(parts, strings.Split(p.pathPrefix, "/")...)
	}
	if path != "" {
		parts = append(parts, strings.Split(path, "/")...)
	}
	for index := range parts {
		parts[index] = pathEscape(parts[index])
	}
	return "/" + strings.Join(parts, "/")
}
