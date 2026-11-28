// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	listPageSize       = 500
	notInstalledWait   = 30 * time.Second
	metadataListAccept = "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1"
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

type collectionSnapshot struct {
	items           []map[string]any
	omitted         []map[string]any
	resourceVersion string
}

type collectionPage struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
	Metadata   struct {
		ResourceVersion string `json:"resourceVersion"`
		Continue        string `json:"continue"`
	} `json:"metadata"`
	Items []map[string]any `json:"items"`
}

// list reads a consistent collection snapshot. A resource that cannot fit in
// one full-object page is identified through Kubernetes' metadata-only list.
func (c *Client) list(ctx context.Context, collectionPath, labelSelector string) (collectionSnapshot, error) {
	var result collectionSnapshot
	next := ""
	pageSize := listPageSize
	for {
		query := url.Values{}
		query.Set("limit", fmt.Sprint(pageSize))
		if next != "" {
			query.Set("continue", next)
		}
		if labelSelector != "" {
			query.Set("labelSelector", labelSelector)
		}
		st, body, err := c.request(ctx, http.MethodGet, collectionPath+"?"+query.Encode(), nil)
		if errors.Is(err, errAPIBodyTooLarge) {
			if pageSize == 1 {
				st, body, err = c.requestAsAccept(ctx, http.MethodGet, collectionPath+"?"+query.Encode(), "application/json", metadataListAccept, nil)
				if err != nil {
					return collectionSnapshot{}, fmt.Errorf("k8s: read metadata for %s: %w", collectionPath, err)
				}
				if st == http.StatusGone {
					return collectionSnapshot{}, errWatchExpired
				}
				if st != http.StatusOK {
					return collectionSnapshot{}, fmt.Errorf("k8s: metadata list %s: status %d", collectionPath, st)
				}
				var page collectionPage
				if err := json.Unmarshal(body, &page); err != nil {
					return collectionSnapshot{}, fmt.Errorf("k8s: decode metadata list %s: %w", collectionPath, err)
				}
				if page.Kind != "PartialObjectMetadataList" || page.APIVersion != "meta.k8s.io/v1" || len(page.Items) != 1 ||
					objectKey(page.Items[0]) == "" || objectResourceVersion(page.Items[0]) == "" {
					return collectionSnapshot{}, fmt.Errorf("k8s: metadata list %s did not identify one resource", collectionPath)
				}
				metadata, _ := page.Items[0]["metadata"].(map[string]any)
				uid, _ := metadata["uid"].(string)
				if uid == "" || len(uid) > 128 || len(objectName(page.Items[0])) > 253 || len(objectNamespace(page.Items[0])) > 63 || len(objectResourceVersion(page.Items[0])) > 128 {
					return collectionSnapshot{}, fmt.Errorf("k8s: metadata list %s returned an invalid resource identity", collectionPath)
				}
				if result.resourceVersion != "" && result.resourceVersion != page.Metadata.ResourceVersion {
					return collectionSnapshot{}, errWatchExpired
				}
				result.resourceVersion = page.Metadata.ResourceVersion
				result.omitted = append(result.omitted, map[string]any{"metadata": map[string]any{
					"name": objectName(page.Items[0]), "namespace": objectNamespace(page.Items[0]),
					"uid": uid, "resourceVersion": objectResourceVersion(page.Items[0]),
				}})
				if page.Metadata.Continue == "" {
					return result, nil
				}
				next = page.Metadata.Continue
				continue
			}
			pageSize = max(1, pageSize/2)
			// A continuation token belongs to its original limit. Start a fresh
			// snapshot so every later page uses the same reduced limit.
			result = collectionSnapshot{}
			next = ""
			continue
		}
		if err != nil {
			return collectionSnapshot{}, err
		}
		if st == http.StatusNotFound {
			return collectionSnapshot{}, errNotInstalled
		}
		if st == http.StatusGone {
			return collectionSnapshot{}, errWatchExpired // the continue token expired; start over
		}
		if st/100 != 2 {
			return collectionSnapshot{}, fmt.Errorf("k8s: list %s: status %d: %s", collectionPath, st, string(body))
		}
		var page collectionPage
		if err := json.Unmarshal(body, &page); err != nil {
			return collectionSnapshot{}, fmt.Errorf("k8s: decode %s list: %w", collectionPath, err)
		}
		if result.resourceVersion != "" && result.resourceVersion != page.Metadata.ResourceVersion {
			return collectionSnapshot{}, errWatchExpired
		}
		result.resourceVersion = page.Metadata.ResourceVersion
		result.items = append(result.items, page.Items...)
		if page.Metadata.Continue == "" {
			return result, nil
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
	omitted   map[string]map[string]any
	synced    bool
	installed bool
	lastErr   error
}

func newInformer(client *Client, path, labelSelector string, onChange func(string, map[string]any)) *informer {
	return &informer{
		client: client, path: path, labelSelector: labelSelector, onChange: onChange,
		watchTimeout: 5 * time.Minute, items: map[string]map[string]any{}, omitted: map[string]map[string]any{},
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
	snapshot, err := i.client.list(ctx, i.path, i.labelSelector)
	if errors.Is(err, errNotInstalled) {
		i.replace(nil, nil, false, err)
		return "", err
	}
	if err != nil {
		return "", err
	}
	i.replace(snapshot.items, snapshot.omitted, true, nil)
	return snapshot.resourceVersion, nil
}

func (i *informer) replace(items, omitted []map[string]any, installed bool, cause error) {
	fresh := make(map[string]map[string]any, len(items))
	for _, obj := range items {
		if key := objectKey(obj); key != "" {
			fresh[key] = obj
		}
	}
	skipped := make(map[string]map[string]any, len(omitted))
	for _, obj := range omitted {
		if key := objectKey(obj); key != "" {
			skipped[key] = obj
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
	i.items, i.omitted, i.synced, i.installed, i.lastErr = fresh, skipped, true, installed, cause
	if len(skipped) > 0 {
		i.lastErr = errAPIBodyTooLarge
	}
	i.mu.Unlock()
	for key := range skipped {
		slog.Warn("k8s informer collection sync skipped oversized resource", "collection", i.path, "resource", key, "cause", "api_response_too_large")
	}
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
		delete(i.omitted, key)
	case "DELETED":
		delete(i.items, key)
		delete(i.omitted, key)
	default:
		i.mu.Unlock()
		return nil
	}
	if len(i.omitted) == 0 {
		i.lastErr = nil
	}
	i.mu.Unlock()
	i.onChange(key, obj)
	return nil
}

func (i *informer) fail(err error) {
	i.mu.Lock()
	i.lastErr = err
	i.mu.Unlock()
	if errors.Is(err, errAPIBodyTooLarge) {
		slog.Warn("k8s informer collection sync failed", "collection", i.path, "cause", "api_response_too_large")
	}
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

func (i *informer) omittedSnapshot() []map[string]any {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make([]map[string]any, 0, len(i.omitted))
	for _, obj := range i.omitted {
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
