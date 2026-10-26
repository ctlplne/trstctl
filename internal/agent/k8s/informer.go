// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// The controller's informers keep a local cache of each resource collection
// current through the Kubernetes list+watch protocol, the same contract
// client-go's reflector implements: list once for a consistent snapshot and its
// resourceVersion, then watch from that version, following bookmarks, and list
// again when the server says the version has expired (410 Gone). Every add,
// change and delete calls onChange with the object's key and the object (for a
// delete, its last known state).

var (
	errWatchExpired = errors.New("k8s: watch resource version expired")
	// errNotInstalled reports that the collection's API (typically a CRD such
	// as cert-manager's) is not served by this cluster.
	errNotInstalled = errors.New("k8s: resource is not installed in this cluster")
)

const (
	listPageSize     = 500
	notInstalledWait = 30 * time.Second
)

// watchEvent is one event from a Kubernetes watch stream.
type watchEvent struct {
	Type   string          `json:"type"`
	Object json.RawMessage `json:"object"`
}

// watch streams events for collectionPath from resourceVersion until the
// server ends the stream (nil), the version expires (errWatchExpired), ctx
// ends, or onEvent fails.
func (c *Client) watch(ctx context.Context, collectionPath, labelSelector, resourceVersion string, timeout time.Duration, onEvent func(watchEvent) error) error {
	query := url.Values{}
	query.Set("watch", "1")
	query.Set("allowWatchBookmarks", "true")
	query.Set("resourceVersion", resourceVersion)
	query.Set("timeoutSeconds", fmt.Sprint(int(timeout/time.Second)))
	if labelSelector != "" {
		query.Set("labelSelector", labelSelector)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+collectionPath+"?"+query.Encode(), nil)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/json")
	// The stream client has no whole-exchange timeout, which would cut every
	// stream; the server-side timeoutSeconds and ctx bound it instead.
	resp, err := c.stream.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusGone:
		return errWatchExpired
	case resp.StatusCode == http.StatusNotFound:
		return errNotInstalled
	case resp.StatusCode/100 != 2:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("k8s: watch %s: status %d: %s", collectionPath, resp.StatusCode, string(body))
	}
	dec := json.NewDecoder(resp.Body)
	for {
		var event watchEvent
		if err := dec.Decode(&event); err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("k8s: read watch %s: %w", collectionPath, err)
		}
		if event.Type == "ERROR" {
			var status struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}
			_ = json.Unmarshal(event.Object, &status)
			if status.Code == http.StatusGone {
				return errWatchExpired
			}
			return fmt.Errorf("k8s: watch %s: %d %s", collectionPath, status.Code, status.Message)
		}
		if err := onEvent(event); err != nil {
			return err
		}
	}
}

// list reads the whole collection page by page and returns its items with the
// snapshot's resourceVersion.
func (c *Client) list(ctx context.Context, collectionPath, labelSelector string) ([]map[string]any, string, error) {
	var items []map[string]any
	snapshot, next := "", ""
	for {
		query := url.Values{}
		query.Set("limit", fmt.Sprint(listPageSize))
		if next != "" {
			query.Set("continue", next)
		}
		if labelSelector != "" {
			query.Set("labelSelector", labelSelector)
		}
		st, body, err := c.request(ctx, http.MethodGet, collectionPath+"?"+query.Encode(), nil)
		if err != nil {
			return nil, "", err
		}
		if st == http.StatusNotFound {
			return nil, "", errNotInstalled
		}
		if st == http.StatusGone {
			return nil, "", errWatchExpired // the continue token expired; start over
		}
		if st/100 != 2 {
			return nil, "", fmt.Errorf("k8s: list %s: status %d: %s", collectionPath, st, string(body))
		}
		var page struct {
			Metadata struct {
				ResourceVersion string `json:"resourceVersion"`
				Continue        string `json:"continue"`
			} `json:"metadata"`
			Items []map[string]any `json:"items"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, "", fmt.Errorf("k8s: decode %s list: %w", collectionPath, err)
		}
		if snapshot == "" {
			snapshot = page.Metadata.ResourceVersion
		}
		items = append(items, page.Items...)
		if page.Metadata.Continue == "" {
			return items, snapshot, nil
		}
		next = page.Metadata.Continue
	}
}

// informer caches one collection and reports every change by key.
type informer struct {
	client        *Client
	path          string
	labelSelector string
	onChange      func(key string, obj map[string]any)
	watchTimeout  time.Duration

	mu        sync.RWMutex
	items     map[string]map[string]any
	synced    bool
	installed bool
	lastErr   error
}

func newInformer(client *Client, path, labelSelector string, onChange func(string, map[string]any)) *informer {
	return &informer{
		client: client, path: path, labelSelector: labelSelector, onChange: onChange,
		watchTimeout: 5 * time.Minute, items: map[string]map[string]any{},
	}
}

// objectKey is namespace/name for namespaced objects and name otherwise.
func objectKey(obj map[string]any) string {
	if namespace := objectNamespace(obj); namespace != "" {
		return namespace + "/" + objectName(obj)
	}
	return objectName(obj)
}

func objectResourceVersion(obj map[string]any) string {
	meta, _ := obj["metadata"].(map[string]any)
	rv, _ := meta["resourceVersion"].(string)
	return rv
}

// run keeps the cache current until ctx ends.
func (i *informer) run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		rv, err := i.relist(ctx)
		switch {
		case errors.Is(err, errNotInstalled):
			sleepCtx(ctx, notInstalledWait)
			continue
		case err != nil:
			i.fail(err)
			sleepCtx(ctx, backoff)
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		for ctx.Err() == nil {
			// Jitter spreads reconnects when several informers share one server.
			timeout := i.watchTimeout - time.Duration(rand.Int64N(int64(i.watchTimeout/4))) // #nosec G404 -- reconnect jitter, not a security decision (CWE-338)
			err = i.client.watch(ctx, i.path, i.labelSelector, rv, timeout, func(event watchEvent) error {
				return i.apply(event, &rv)
			})
			if err == nil {
				continue // the server closed the stream on schedule; resume from rv
			}
			if !errors.Is(err, errWatchExpired) && ctx.Err() == nil {
				i.fail(err)
				sleepCtx(ctx, backoff)
				backoff = min(backoff*2, 30*time.Second)
			}
			break // list again
		}
	}
}

// relist replaces the cache with a fresh snapshot, reporting what differs.
func (i *informer) relist(ctx context.Context) (string, error) {
	items, rv, err := i.client.list(ctx, i.path, i.labelSelector)
	if errors.Is(err, errNotInstalled) {
		i.replace(nil, false, err)
		return "", err
	}
	if err != nil {
		return "", err
	}
	i.replace(items, true, nil)
	return rv, nil
}

func (i *informer) replace(items []map[string]any, installed bool, cause error) {
	fresh := make(map[string]map[string]any, len(items))
	for _, obj := range items {
		if key := objectKey(obj); key != "" {
			fresh[key] = obj
		}
	}
	i.mu.Lock()
	changed := map[string]map[string]any{}
	for key, obj := range fresh {
		if old, ok := i.items[key]; !ok || objectResourceVersion(old) != objectResourceVersion(obj) {
			changed[key] = obj
		}
	}
	for key, old := range i.items {
		if _, ok := fresh[key]; !ok {
			changed[key] = old
		}
	}
	i.items, i.synced, i.installed, i.lastErr = fresh, true, installed, cause
	i.mu.Unlock()
	for key, obj := range changed {
		i.onChange(key, obj)
	}
}

func (i *informer) apply(event watchEvent, rv *string) error {
	var obj map[string]any
	if err := json.Unmarshal(event.Object, &obj); err != nil {
		return fmt.Errorf("k8s: decode watch event for %s: %w", i.path, err)
	}
	if version := objectResourceVersion(obj); version != "" {
		*rv = version
	}
	if event.Type == "BOOKMARK" {
		return nil
	}
	key := objectKey(obj)
	if key == "" {
		return nil
	}
	i.mu.Lock()
	switch event.Type {
	case "ADDED", "MODIFIED":
		i.items[key] = obj
	case "DELETED":
		delete(i.items, key)
	default:
		i.mu.Unlock()
		return nil
	}
	i.lastErr = nil
	i.mu.Unlock()
	i.onChange(key, obj)
	return nil
}

func (i *informer) fail(err error) {
	i.mu.Lock()
	i.lastErr = err
	i.mu.Unlock()
}

// get returns a private copy of the cached object.
func (i *informer) get(key string) (map[string]any, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	obj, ok := i.items[key]
	if !ok {
		return nil, false
	}
	return deepCopyObject(obj), true
}

// keys lists every cached key.
func (i *informer) keys() []string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make([]string, 0, len(i.items))
	for key := range i.items {
		out = append(out, key)
	}
	return out
}

// snapshot returns private copies of every cached object.
func (i *informer) snapshot() []map[string]any {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make([]map[string]any, 0, len(i.items))
	for _, obj := range i.items {
		out = append(out, deepCopyObject(obj))
	}
	return out
}

// state reports whether the first list finished, whether the API exists, and
// the last list/watch error.
func (i *informer) state() (synced, installed bool, lastErr error) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.synced, i.installed, i.lastErr
}

func deepCopyObject(obj map[string]any) map[string]any {
	out, _ := deepCopyJSON(obj).(map[string]any)
	return out
}

func deepCopyJSON(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = deepCopyJSON(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for index, item := range v {
			out[index] = deepCopyJSON(item)
		}
		return out
	default:
		return v
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
