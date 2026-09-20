// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"time"
)

// B-4: code signing served the two mutations (sign with a managed key, sign
// keylessly) and nothing that answered afterwards: which identities signed,
// and did the transparency-log entry actually land. Rekor publication rides
// the outbox, and the Rekor handler refuses to acknowledge an entry whose
// signed receipt does not verify — so a delivered transparency row IS a
// verified entry. This view reports that state rather than inventing a
// parallel flag that could disagree with the outbox.
//
// It reads no sealed command bytes: the plaintext identity assertion and the
// artifact digest never leave the signer boundary, and nothing here changes
// that.

// CodeSigningIdentity is one signing operation and its transparency state.
type CodeSigningIdentity struct {
	OperationID string `json:"operation_id"`
	// Mode is the signing identity kind: "managed" for a signer-held key,
	// "keyless" for an ephemeral Sigstore/Fulcio identity.
	Mode        string `json:"mode"`
	Status      string `json:"status"`
	RequestHash string `json:"request_hash"`
	// Transparency is "verified", "pending", "failed", or "not-published".
	Transparency      string    `json:"transparency"`
	TransparencyError string    `json:"transparency_error,omitempty"`
	LastError         string    `json:"last_error,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// CodeSigningIdentityList is the served answer plus the counts a reviewer asks
// for first: how many signatures exist, and how many are publicly verifiable.
type CodeSigningIdentityList struct {
	Items             []CodeSigningIdentity `json:"items"`
	Total             int                   `json:"total"`
	VerifiedCount     int                   `json:"verified_count"`
	NotPublishedCount int                   `json:"not_published_count"`
}

// CodeSigningIdentityProvider is the server-side seam over the store join.
type CodeSigningIdentityProvider func(ctx context.Context, tenantID string) ([]CodeSigningIdentity, error)

func (a *API) listCodeSigningIdentities(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.codeSigningIdentities == nil {
		a.writeJSON(w, http.StatusOK, CodeSigningIdentityList{Items: []CodeSigningIdentity{}})
		return
	}
	items, err := a.codeSigningIdentities(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	list := CodeSigningIdentityList{Items: []CodeSigningIdentity{}}
	for _, item := range items {
		list.Items = append(list.Items, item)
		switch item.Transparency {
		case "verified":
			list.VerifiedCount++
		case "not-published":
			list.NotPublishedCount++
		}
	}
	list.Total = len(list.Items)
	a.writeJSON(w, http.StatusOK, list)
}
