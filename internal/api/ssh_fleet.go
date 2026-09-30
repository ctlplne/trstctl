// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"time"
)

// B-2: the SSH surface served CA status, rollouts, and revocation — everything
// about the credentials trstctl issues — and nothing about the credentials it
// does not. Discovered SSH keys sat in the inventory with no view that answered
// the question an operator actually has: which hosts still have standing
// key-based access that certificate rotation cannot reach.
//
// The rows identify key locations and standing grants. A raw public key can
// also be the key inside a CA-signed host certificate, so key inventory alone
// cannot establish whether the host trusts or serves an SSH CA certificate.

// SSHFleetHost is one discovered SSH key location and its grant counts.
type SSHFleetHost struct {
	Location string `json:"location"`
	Keys     int    `json:"keys"`
	// StandingKeys confer persistent login — the ones that outlive a rotation.
	StandingKeys int `json:"standing_keys"`
	// OrphanedKeys have no attributable owner, so nobody will notice them going
	// stale and nobody can be asked to remove them.
	OrphanedKeys  int       `json:"orphaned_keys"`
	KeyTypes      []string  `json:"key_types"`
	Sources       []string  `json:"sources"`
	FirstObserved time.Time `json:"first_observed"`
	LastObserved  time.Time `json:"last_observed"`
}

// SSHFleetInventory is the served answer plus the counts worth acting on.
type SSHFleetInventory struct {
	Hosts            []SSHFleetHost `json:"hosts"`
	// HostCount is a legacy wire name for the number of reported key locations.
	HostCount        int            `json:"host_count"`
	KeyCount         int            `json:"key_count"`
	StandingKeyCount int            `json:"standing_key_count"`
	OrphanedKeyCount int            `json:"orphaned_key_count"`
}

// SSHFleetProvider is the server-side seam over the store aggregate.
type SSHFleetProvider func(ctx context.Context, tenantID string) ([]SSHFleetHost, error)

func (a *API) getSSHFleet(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.sshFleet == nil {
		a.writeJSON(w, http.StatusOK, SSHFleetInventory{Hosts: []SSHFleetHost{}})
		return
	}
	hosts, err := a.sshFleet(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	inventory := SSHFleetInventory{Hosts: []SSHFleetHost{}}
	for _, host := range hosts {
		if host.KeyTypes == nil {
			host.KeyTypes = []string{}
		}
		if host.Sources == nil {
			host.Sources = []string{}
		}
		inventory.Hosts = append(inventory.Hosts, host)
		inventory.KeyCount += host.Keys
		inventory.StandingKeyCount += host.StandingKeys
		inventory.OrphanedKeyCount += host.OrphanedKeys
	}
	inventory.HostCount = len(inventory.Hosts)
	a.writeJSON(w, http.StatusOK, inventory)
}
