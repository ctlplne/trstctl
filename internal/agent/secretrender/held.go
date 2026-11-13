// SPDX-License-Identifier: BUSL-1.1

package secretrender

import (
	"bytes"
	"slices"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// heldLeases keeps each lease credential the renderer issued in locked memory
// (AN-8) while the lease serves its file, so a file written again (a static
// secret changed, or the file went) keeps its live leases instead of issuing
// new ones (A238-L4). One credential is held per template and lease
// reference. The state file stays free of values, so a restarted renderer
// holds nothing and issues fresh leases when it next writes a file.
type heldLeases struct {
	mu sync.Mutex
	m  map[string]heldLease
}

type heldLease struct {
	id   string
	cred *secret.Buffer
}

func heldKey(template, ref string) string { return template + "\x00" + ref }

// put holds a copy of a newly issued lease's credential, destroying the one
// held for the reference before. It reports whether the copy is held.
func (h *heldLeases) put(template, ref, id string, credential []byte) bool {
	buf, err := secret.NewFrom(credential)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dropLocked(heldKey(template, ref))
	if err != nil {
		return false
	}
	if h.m == nil {
		h.m = map[string]heldLease{}
	}
	h.m[heldKey(template, ref)] = heldLease{id: id, cred: buf}
	return true
}

// get returns a copy of the credential held for the reference's lease id, or
// nil when none is held for that lease. The caller wipes the copy.
func (h *heldLeases) get(template, ref, id string) []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	held, ok := h.m[heldKey(template, ref)]
	if !ok || held.id != id {
		return nil
	}
	var out []byte
	_ = held.cred.Use(func(b []byte) error {
		out = bytes.Clone(b)
		return nil
	})
	return out
}

// keep destroys the credentials held for a template's references other than
// refs (nil drops all of the template's).
func (h *heldLeases) keep(template string, refs []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	prefix := heldKey(template, "")
	for key := range h.m {
		if ref, ok := strings.CutPrefix(key, prefix); ok && !slices.Contains(refs, ref) {
			h.dropLocked(key)
		}
	}
}

// destroyAll destroys every held credential.
func (h *heldLeases) destroyAll() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for key := range h.m {
		h.dropLocked(key)
	}
}

func (h *heldLeases) dropLocked(key string) {
	if held, ok := h.m[key]; ok {
		held.cred.Destroy()
		delete(h.m, key)
	}
}
