// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/secretscan"
	"trstctl.com/trstctl/internal/store"
)

// Moving a leaked secret into the native store (P6). The CLI re-finds the value
// in the operator's own checkout, stores it with POST /api/v1/secrets/store,
// then links the finding here: only the secret's name and version and the
// history commits that still hold the value cross this call, never the value.
// The finding then closes on evidence alone (the leader's closure worker): a
// rotation of the secret, a consumer reading the rotated version, and a
// completed scan that no longer sees the leak. History residue stays listed
// on the finding after it closes.

const leakedSecretFindingKind = "leaked_secret" // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)

// movedSecretReadBatch bounds the moved findings one secret read can attest.
const movedSecretReadBatch = 20

var residueCommit = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

type discoveryFindingSecretMoveRequest struct {
	SecretName     string                        `json:"secret_name"`
	SecretVersion  int                           `json:"secret_version"`
	HistoryResidue []store.SecretResidueLocation `json:"history_residue"`
}

// discoveryFindingSecretMoveResponse is a moved finding's link to its secret.
type discoveryFindingSecretMoveResponse struct {
	SecretName          string                        `json:"secret_name"`
	SecretVersion       int                           `json:"secret_version"`
	Reference           string                        `json:"reference"`
	MovedBy             string                        `json:"moved_by,omitempty"`
	MovedAt             time.Time                     `json:"moved_at"`
	HistoryResidue      []store.SecretResidueLocation `json:"history_residue"`
	ConsumerReadVersion int                           `json:"consumer_read_version,omitempty"`
	ConsumerReader      string                        `json:"consumer_reader,omitempty"`
	ConsumerReadAt      *time.Time                    `json:"consumer_read_at,omitempty"`
}

func toSecretMoveResponse(m store.DiscoveryFindingSecretMove) *discoveryFindingSecretMoveResponse {
	residue := m.Residue
	if residue == nil {
		residue = []store.SecretResidueLocation{}
	}
	return &discoveryFindingSecretMoveResponse{
		SecretName: m.SecretName, SecretVersion: m.SecretVersion, Reference: "${secret." + m.SecretName + "}",
		MovedBy: m.MovedBy, MovedAt: m.MovedAt, HistoryResidue: residue,
		ConsumerReadVersion: m.ConsumerReadVersion, ConsumerReader: m.ConsumerReader, ConsumerReadAt: m.ConsumerReadAt,
	}
}

func (req *discoveryFindingSecretMoveRequest) validate() error {
	req.SecretName = strings.TrimSpace(req.SecretName)
	switch {
	case req.SecretName == "" || len(req.SecretName) > 512:
		return errors.New("secret_name is required (at most 512 characters)")
	case req.SecretVersion < 1:
		return errors.New("secret_version must be the stored secret's version")
	case len(req.HistoryResidue) > secretscan.MaxSecretResidue:
		return errors.New("history_residue holds at most 100 locations")
	}
	for _, loc := range req.HistoryResidue {
		if loc.RuleID == "" || len(loc.RuleID) > 128 || loc.File == "" || len(loc.File) > 1024 || loc.Line < 1 || !residueCommit.MatchString(loc.Commit) {
			return errors.New("each history_residue location needs a rule_id, a file, a line and a commit SHA")
		}
	}
	return nil
}

// moveDiscoveryFindingSecret links a leaked-secret finding to the native
// secret version its value moved into.
//
//trstctl:mutation
func (a *API) moveDiscoveryFindingSecret(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req discoveryFindingSecretMoveRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		id := r.PathValue("id")
		if _, err := googleuuid.Parse(id); err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, "id must be a valid UUID")
		}
		if err := req.validate(); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		f, err := a.store.GetDiscoveryFinding(ctx, tenantID, id)
		if err != nil {
			return 0, nil, discoveryTriageError(err)
		}
		if f.Kind != leakedSecretFindingKind {
			return 0, nil, errStatus(http.StatusConflict, "only a leaked-secret finding moves into the secret store")
		}
		// A235-L2: a secret in a restricted environment the caller is not
		// granted answers exactly as a missing one, so the move is no
		// existence or version oracle.
		readErr := a.requireSecretRead(ctx, tenantID, req.SecretName)
		if readErr == nil {
			_, readErr = a.store.GetSecretVersion(ctx, tenantID, req.SecretName, req.SecretVersion)
		}
		if err := readErr; err != nil {
			if errors.Is(err, store.ErrSecretNotFound) {
				return 0, nil, errStatus(http.StatusConflict, "store the value first: the named secret version does not exist")
			}
			return 0, nil, err
		}
		resp := toDiscoveryFindingResponse(f)
		existing, moved, err := a.store.GetDiscoveryFindingSecretMove(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		if moved {
			if existing.SecretName != req.SecretName || existing.SecretVersion != req.SecretVersion {
				return 0, nil, errStatus(http.StatusConflict, "the finding already moved into another secret")
			}
			resp.SecretMove = toSecretMoveResponse(existing)
			return http.StatusOK, resp, nil
		}
		principal, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		m, err := a.orch.RecordDiscoveryFindingSecretMoved(ctx, tenantID, projections.DiscoveryFindingSecretMoved{
			FindingID: id, SecretName: req.SecretName, SecretVersion: req.SecretVersion,
			MovedBy: principal, Residue: req.HistoryResidue,
		})
		if err != nil {
			return 0, nil, err
		}
		resp.SecretMove = toSecretMoveResponse(m)
		return http.StatusOK, resp, nil
	})
}

// withSecretMoves fills each listed finding's link to the secret it moved into.
func (a *API) withSecretMoves(ctx context.Context, tenantID string, items []discoveryFindingResponse) error {
	ids := make([]string, 0, len(items))
	for _, item := range items {
		if item.Kind == leakedSecretFindingKind {
			ids = append(ids, item.ID)
		}
	}
	moves, err := a.store.DiscoveryFindingSecretMovesFor(ctx, tenantID, ids)
	if err != nil {
		return err
	}
	for i := range items {
		if m, ok := moves[items[i].ID]; ok {
			items[i].SecretMove = toSecretMoveResponse(m)
		}
	}
	return nil
}

// observeMovedSecretRead records that a consumer read a version of a moved
// leaked secret newer than the moved one: the evidence that the secret's
// consumers picked up its rotation. A failure to record is logged and never
// fails the read; without the record the finding only stays open.
func (a *API) observeMovedSecretRead(r *http.Request, tenantID, name string, version int) {
	a.observeMovedSecretReadBy(r.Context(), tenantID, name, version, func() (string, error) {
		return requestPrincipalSubject(r.Context())
	})
}

// ObserveMovedSecretDelivery records that a secret-sync target received a
// version of a moved leaked secret newer than the moved one (P6-L4): its
// consumers read the secret there, so the delivery is their read, by the
// reader "secret-sync:<target>". Like a read, a failure to record is logged
// and never fails the delivery.
func (a *API) ObserveMovedSecretDelivery(ctx context.Context, tenantID, name string, version int, target string) {
	a.observeMovedSecretReadBy(ctx, tenantID, name, version, func() (string, error) {
		return "secret-sync:" + target, nil
	})
}

// observeMovedSecretReadBy names the reader only when a moved finding is
// waiting for one, so an ordinary read costs one indexed lookup.
func (a *API) observeMovedSecretReadBy(ctx context.Context, tenantID, name string, version int, readerOf func() (string, error)) {
	if a.orch == nil || a.store == nil || version < 2 {
		return
	}
	ids, err := a.store.MovedFindingsAwaitingConsumerRead(ctx, tenantID, name, version, movedSecretReadBatch)
	if err == nil && len(ids) > 0 {
		var reader string
		if reader, err = readerOf(); err == nil {
			now := time.Now().UTC()
			for _, id := range ids {
				if recErr := a.orch.RecordMovedSecretConsumerRead(ctx, tenantID, projections.DiscoveryFindingSecretConsumerRead{
					FindingID: id, SecretName: name, Version: version, Reader: reader, ReadAt: now,
				}); recErr != nil && err == nil {
					err = recErr
				}
			}
		}
	}
	if err != nil {
		slog.Warn("api: a moved secret's consumer read was not recorded",
			slog.String("types", errorTypeChain(err)), slog.String("error", redactQuoted(truncateForLog(err.Error(), 240))))
	}
}
