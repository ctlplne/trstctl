// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// fakeAPI is an in-memory Kubernetes API server with the list+watch contract
// the informers rely on: a cluster-wide resourceVersion, collection lists that
// carry it, watch streams of ADDED/MODIFIED/DELETED events from a version, a
// status subresource, label-selected collections, and a switch that makes the
// next watch of a collection answer 410 Gone. A resource that was never
// registered answers 404, as an uninstalled CRD does.
type fakeAPI struct {
	mu        sync.Mutex
	rv        int
	resources map[string]bool                      // "group/version/resource"
	objects   map[string]map[string]map[string]any // resource -> namespace/name -> object
	history   []fakeEvent
	notify    chan struct{}
	gone      map[string]bool
	writes    map[string]int // "METHOD resource" -> count
}

type fakeEvent struct {
	rv       int
	resource string
	kind     string
	object   map[string]any
}

func newFakeAPI(resources ...string) *fakeAPI {
	f := &fakeAPI{
		resources: map[string]bool{}, objects: map[string]map[string]map[string]any{},
		notify: make(chan struct{}), gone: map[string]bool{}, writes: map[string]int{},
	}
	for _, resource := range resources {
		f.resources[resource] = true
		f.objects[resource] = map[string]map[string]any{}
	}
	return f
}

// fakePath splits an API path into its resource, namespace, name and
// subresource. Core paths have no group.
func fakePath(path string) (resource, namespace, name, sub string, ok bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	var gv string
	switch {
	case len(parts) >= 2 && parts[0] == "api":
		gv, parts = parts[1], parts[2:]
	case len(parts) >= 3 && parts[0] == "apis":
		gv, parts = parts[1]+"/"+parts[2], parts[3:]
	default:
		return "", "", "", "", false
	}
	if len(parts) >= 2 && parts[0] == "namespaces" {
		namespace, parts = parts[1], parts[2:]
	}
	if len(parts) == 0 {
		return "", "", "", "", false
	}
	resource = gv + "/" + parts[0]
	if len(parts) > 1 {
		name = parts[1]
	}
	if len(parts) > 2 {
		sub = parts[2]
	}
	return resource, namespace, name, sub, true
}

func fakeKey(namespace, name string) string { return namespace + "/" + name }

func fakeMeta(obj map[string]any) map[string]any {
	meta, _ := obj["metadata"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
		obj["metadata"] = meta
	}
	return meta
}

// put stores obj (assigning a version and uid) and records the event.
func (f *fakeAPI) putLocked(resource, kind string, obj map[string]any) map[string]any {
	f.rv++
	meta := fakeMeta(obj)
	meta["resourceVersion"] = strconv.Itoa(f.rv)
	if meta["uid"] == nil {
		meta["uid"] = fmt.Sprintf("uid-%d", f.rv)
	}
	namespace, _ := meta["namespace"].(string)
	name, _ := meta["name"].(string)
	stored := deepCopyObject(obj)
	if kind == "DELETED" {
		delete(f.objects[resource], fakeKey(namespace, name))
	} else {
		f.objects[resource][fakeKey(namespace, name)] = stored
	}
	f.history = append(f.history, fakeEvent{rv: f.rv, resource: resource, kind: kind, object: deepCopyObject(stored)})
	close(f.notify)
	f.notify = make(chan struct{})
	return deepCopyObject(stored)
}

// seed creates an object as an outside actor would.
func (f *fakeAPI) seed(resource string, obj map[string]any) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.putLocked(resource, "ADDED", deepCopyObject(obj))
}

// mutate changes a stored object as an outside actor would.
func (f *fakeAPI) mutate(resource, namespace, name string, change func(map[string]any)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj := deepCopyObject(f.objects[resource][fakeKey(namespace, name)])
	change(obj)
	f.putLocked(resource, "MODIFIED", obj)
}

// remove deletes a stored object as an outside actor would.
func (f *fakeAPI) remove(resource, namespace, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if obj, ok := f.objects[resource][fakeKey(namespace, name)]; ok {
		f.putLocked(resource, "DELETED", deepCopyObject(obj))
	}
}

func (f *fakeAPI) get(resource, namespace, name string) (map[string]any, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj, ok := f.objects[resource][fakeKey(namespace, name)]
	return deepCopyObject(obj), ok
}

// writeCount reports how many writes of method reached resource.
func (f *fakeAPI) writeCount(method, resource string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.writes[method+" "+resource]
}

func (f *fakeAPI) totalWrites() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	total := 0
	for _, n := range f.writes {
		total += n
	}
	return total
}

func (f *fakeAPI) expireWatches(resource string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gone[resource] = true
	close(f.notify)
	f.notify = make(chan struct{})
}

func fakeLabelsMatch(obj map[string]any, selector string) bool {
	if selector == "" {
		return true
	}
	labels, _ := fakeMeta(obj)["labels"].(map[string]any)
	for _, term := range strings.Split(selector, ",") {
		key, value, _ := strings.Cut(term, "=")
		if got, _ := labels[key].(string); got != value {
			return false
		}
	}
	return true
}

func (f *fakeAPI) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resource, namespace, name, sub, ok := fakePath(r.URL.Path)
		f.mu.Lock()
		known := ok && f.resources[resource]
		f.mu.Unlock()
		if !known {
			http.Error(w, `{"kind":"Status","code":404}`, http.StatusNotFound)
			return
		}
		if r.Method == http.MethodGet && name == "" && r.URL.Query().Get("watch") == "1" {
			f.serveWatch(w, r, resource, namespace)
			return
		}
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Method != http.MethodGet {
			f.writes[r.Method+" "+resource]++
		}
		selector := r.URL.Query().Get("labelSelector")
		switch {
		case r.Method == http.MethodGet && name == "":
			items := []map[string]any{}
			for _, obj := range f.objects[resource] {
				objNamespace, _ := fakeMeta(obj)["namespace"].(string)
				if (namespace == "" || objNamespace == namespace) && fakeLabelsMatch(obj, selector) {
					items = append(items, deepCopyObject(obj))
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"metadata": map[string]any{"resourceVersion": strconv.Itoa(f.rv)}, "items": items,
			})
		case r.Method == http.MethodGet:
			obj, ok := f.objects[resource][fakeKey(namespace, name)]
			if !ok {
				http.Error(w, `{"kind":"Status","code":404}`, http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(obj)
		case r.Method == http.MethodPost && name == "":
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			meta := fakeMeta(obj)
			if namespace != "" {
				meta["namespace"] = namespace
			}
			objName, _ := meta["name"].(string)
			if _, exists := f.objects[resource][fakeKey(namespace, objName)]; exists {
				http.Error(w, `{"kind":"Status","code":409}`, http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(f.putLocked(resource, "ADDED", obj))
		case r.Method == http.MethodPut:
			live, ok := f.objects[resource][fakeKey(namespace, name)]
			if !ok {
				http.Error(w, `{"kind":"Status","code":404}`, http.StatusNotFound)
				return
			}
			var obj map[string]any
			_ = json.Unmarshal(body, &obj)
			if rv, _ := fakeMeta(obj)["resourceVersion"].(string); rv != "" && rv != fakeMeta(live)["resourceVersion"] {
				http.Error(w, `{"kind":"Status","code":409}`, http.StatusConflict)
				return
			}
			updated := deepCopyObject(live)
			if sub == "status" {
				updated["status"] = obj["status"]
			} else {
				obj["status"] = live["status"]
				fakeMeta(obj)["uid"] = fakeMeta(live)["uid"]
				fakeMeta(obj)["namespace"] = namespace
				updated = obj
			}
			_ = json.NewEncoder(w).Encode(f.putLocked(resource, "MODIFIED", updated))
		case r.Method == http.MethodDelete:
			obj, ok := f.objects[resource][fakeKey(namespace, name)]
			if !ok {
				http.Error(w, `{"kind":"Status","code":404}`, http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(f.putLocked(resource, "DELETED", deepCopyObject(obj)))
		default:
			http.Error(w, "unsupported", http.StatusMethodNotAllowed)
		}
	})
}

// serveWatch streams the collection's events after the requested version
// until the client goes away, the timeout passes, or the watch is expired.
func (f *fakeAPI) serveWatch(w http.ResponseWriter, r *http.Request, resource, namespace string) {
	from, _ := strconv.Atoi(r.URL.Query().Get("resourceVersion"))
	selector := r.URL.Query().Get("labelSelector")
	timeoutSeconds, _ := strconv.Atoi(r.URL.Query().Get("timeoutSeconds"))
	deadline := time.After(time.Duration(max(timeoutSeconds, 1)) * time.Second)
	f.mu.Lock()
	if f.gone[resource] {
		delete(f.gone, resource)
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "ERROR", "object": map[string]any{"kind": "Status", "code": 410, "message": "too old resource version"}})
		return
	}
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}
	sent := from
	for {
		f.mu.Lock()
		if f.gone[resource] {
			delete(f.gone, resource)
			f.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"type": "ERROR", "object": map[string]any{"kind": "Status", "code": 410}})
			return
		}
		var pending []fakeEvent
		for _, event := range f.history {
			if event.rv > sent && event.resource == resource {
				objNamespace, _ := fakeMeta(event.object)["namespace"].(string)
				if (namespace == "" || objNamespace == namespace) && fakeLabelsMatch(event.object, selector) {
					pending = append(pending, event)
				}
			}
		}
		if len(f.history) > 0 {
			sent = max(sent, f.history[len(f.history)-1].rv)
		}
		wake := f.notify
		f.mu.Unlock()
		for _, event := range pending {
			if err := json.NewEncoder(w).Encode(map[string]any{"type": event.kind, "object": event.object}); err != nil {
				return
			}
		}
		if flusher != nil && len(pending) > 0 {
			flusher.Flush()
		}
		select {
		case <-r.Context().Done():
			return
		case <-deadline:
			return
		case <-wake:
		}
	}
}
