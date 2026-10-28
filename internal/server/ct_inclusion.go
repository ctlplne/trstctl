// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto/ctlog"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const (
	ctInclusionInterval      = 10 * time.Minute
	ctInclusionFirstDelay    = 2 * time.Minute
	ctInclusionTenantTimeout = 5 * time.Minute
	ctInclusionBatch         = 64
	// ctMaximumMergeDelay is the 24-hour maximum merge delay RFC 6962 logs
	// publish: a log promises the entry is in its tree by then.
	ctMaximumMergeDelay = 24 * time.Hour
)

var (
	// errCTTreeHeadSignature is a tree head the log key does not verify: a
	// log fault, not a pending merge.
	errCTTreeHeadSignature = errors.New("the log's signed tree head does not verify with its key")
	// errCTNoRFC6962Proofs is a log that serves no get-sth, as static CT API
	// logs do: inclusion cannot be checked through RFC 6962.
	errCTNoRFC6962Proofs = errors.New("the log serves no RFC 6962 get-sth, so its inclusion is not checked here")
)

// RunCTInclusionScheduler proves, on the leader, that the entry behind each
// verified SCT is in its log (A213): it fetches the log's signed tree head,
// checks its signature with the log key the SCT verified against, asks for the
// entry's audit path and checks that it leads to the signed root. Each run is
// bounded per tenant; an entry the log has not merged stays pending until a
// tree head the log signs after its maximum merge delay still lacks it.
func (s *Server) RunCTInclusionScheduler(ctx context.Context) {
	timer := time.NewTimer(ctInclusionFirstDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if err := s.RunCTInclusionOnce(ctx); err != nil && ctx.Err() == nil && s.logger != nil {
			s.logger.Error("CT inclusion check failed", slog.String("error", err.Error()))
		}
		timer.Reset(ctInclusionInterval)
	}
}

// RunCTInclusionOnce checks every tenant's pending SCTs once.
func (s *Server) RunCTInclusionOnce(ctx context.Context) error {
	if s == nil || s.store == nil || s.orch == nil {
		return errors.New("server: CT inclusion checks are not assembled")
	}
	tenants, err := s.store.TenantsWithPendingCTInclusions(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, tenantID := range tenants {
		tenantCtx, cancel := context.WithTimeout(ctx, ctInclusionTenantTimeout)
		err := s.checkTenantCTInclusions(tenantCtx, tenantID)
		cancel()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("tenant %s: %w", tenantID, err))
		}
	}
	return errors.Join(errs...)
}

// ctTreeHead is one log's verified tree head for a run, or why there is none.
type ctTreeHead struct {
	sth ctlog.SignedTreeHead
	err error
}

func (s *Server) checkTenantCTInclusions(ctx context.Context, tenantID string) error {
	pending, err := s.store.PendingCertificateSCTInclusions(ctx, tenantID, ctInclusionBatch)
	if err != nil {
		return err
	}
	heads := map[string]ctTreeHead{}
	var errs []error
	for _, sct := range pending {
		result, decided, err := checkCTInclusion(ctx, sct, heads)
		if err != nil {
			errs = append(errs, fmt.Errorf("submission %s: %w", sct.SubmissionID, err))
			continue
		}
		if !decided {
			continue
		}
		raw, err := json.Marshal(result)
		if err != nil {
			return err
		}
		eventID := uuid.NewSHA1(ctSubmissionNamespace, append([]byte(projections.EventCertificateSCTInclusion+"\x00"), raw...)).String()
		if err := s.orch.RecordCertificateSCTInclusionWithEventID(ctx, tenantID, eventID, result); err != nil {
			errs = append(errs, fmt.Errorf("submission %s: %w", sct.SubmissionID, err))
		}
	}
	return errors.Join(errs...)
}

// checkCTInclusion asks an SCT's log for the entry's audit path against a tree
// head it verified. decided is false while the entry may still be merged or
// the log could not be read.
func checkCTInclusion(ctx context.Context, sct store.CertificateSCT, heads map[string]ctTreeHead) (projections.CertificateSCTInclusion, bool, error) {
	result := projections.CertificateSCTInclusion{SubmissionID: sct.SubmissionID}
	leafHash, err := hex.DecodeString(sct.LeafHash)
	if err != nil || len(leafHash) != 32 {
		return result, false, errors.New("the recorded leaf hash is malformed")
	}
	client, err := cloudHTTPClient(sct.LogURL, sct.AllowPrivateEndpoint, sct.PrivateEgressCIDRs)
	if err != nil {
		return result, false, err
	}
	key := sct.LogURL + "\x00" + hex.EncodeToString(sct.LogPublicKey)
	head, seen := heads[key]
	if !seen {
		head.sth, head.err = fetchCTSignedTreeHead(ctx, client, sct.LogURL, sct.LogPublicKey)
		heads[key] = head
	}
	switch {
	case errors.Is(head.err, errCTTreeHeadSignature):
		result.Status, result.Reason = store.InclusionProofBad, head.err.Error()
		return result, true, nil
	case errors.Is(head.err, errCTNoRFC6962Proofs):
		result.Status, result.Reason = store.InclusionNotChecked, head.err.Error()
		return result, true, nil
	case head.err != nil:
		return result, false, head.err
	}
	proof, found := ctlog.InclusionProof{}, false
	if head.sth.TreeSize > 0 {
		if proof, found, err = fetchCTInclusionProof(ctx, client, sct.LogURL, leafHash, head.sth.TreeSize); err != nil {
			return result, false, err
		}
	}
	if !found {
		mergeBy := uint64(sct.SCTTimestamp.Add(ctMaximumMergeDelay).UnixMilli()) // #nosec G115 -- a log timestamp after 1970 (CWE-190)
		if head.sth.Timestamp < mergeBy {
			return result, false, nil
		}
		result.Status = store.InclusionNotIncluded
		result.Reason = fmt.Sprintf("the tree head the log signed at %s (size %d) does not include the entry, %s after its SCT",
			time.UnixMilli(int64(head.sth.Timestamp)).UTC().Format(time.RFC3339), head.sth.TreeSize, ctMaximumMergeDelay) // #nosec G115 -- a log timestamp in milliseconds fits int64 (CWE-190)
		return result, true, nil
	}
	if err := ctlog.VerifyInclusion(leafHash, proof.LeafIndex, head.sth.TreeSize, proof.AuditPath, head.sth.RootHash); err != nil {
		result.Status, result.Reason = store.InclusionProofBad, err.Error()
		return result, true, nil
	}
	index, size := int64(proof.LeafIndex), int64(head.sth.TreeSize) // #nosec G115 -- a log's tree fits int64 (CWE-190)
	result.Status, result.LeafIndex, result.TreeSize = store.InclusionVerified, &index, &size
	result.RootHash = hex.EncodeToString(head.sth.RootHash)
	return result, true, nil
}

// fetchCTSignedTreeHead reads a log's get-sth and checks its signature.
func fetchCTSignedTreeHead(ctx context.Context, client *http.Client, logURL string, logKey []byte) (ctlog.SignedTreeHead, error) {
	body, status, err := ctLogGet(ctx, client, logURL, "/ct/v1/get-sth", nil)
	if err != nil {
		return ctlog.SignedTreeHead{}, err
	}
	if status == http.StatusNotFound {
		return ctlog.SignedTreeHead{}, errCTNoRFC6962Proofs
	}
	if status != http.StatusOK {
		return ctlog.SignedTreeHead{}, fmt.Errorf("get-sth from %s returned %d", logURL, status)
	}
	sth, err := ctlog.ParseSignedTreeHead(body)
	if err != nil {
		return ctlog.SignedTreeHead{}, err
	}
	if err := ctlog.VerifySignedTreeHead(sth, logKey); err != nil {
		return ctlog.SignedTreeHead{}, fmt.Errorf("%w: %v", errCTTreeHeadSignature, err)
	}
	return sth, nil
}

// fetchCTInclusionProof asks a log for an entry's audit path in a tree of the
// given size; found is false when the log answers 404, as RFC 6962 logs do for
// an entry not in that tree.
func fetchCTInclusionProof(ctx context.Context, client *http.Client, logURL string, leafHash []byte, treeSize uint64) (ctlog.InclusionProof, bool, error) {
	query := url.Values{
		"hash":      {base64.StdEncoding.EncodeToString(leafHash)},
		"tree_size": {strconv.FormatUint(treeSize, 10)},
	}
	body, status, err := ctLogGet(ctx, client, logURL, "/ct/v1/get-proof-by-hash", query)
	if err != nil {
		return ctlog.InclusionProof{}, false, err
	}
	switch status {
	case http.StatusOK:
		proof, err := ctlog.ParseInclusionProof(body)
		return proof, err == nil, err
	case http.StatusNotFound:
		return ctlog.InclusionProof{}, false, nil
	default:
		return ctlog.InclusionProof{}, false, fmt.Errorf("get-proof-by-hash from %s returned %d", logURL, status)
	}
}

func ctLogGet(ctx context.Context, client *http.Client, logURL, path string, query url.Values) ([]byte, int, error) {
	base, err := url.Parse(strings.TrimSpace(logURL))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, 0, fmt.Errorf("server: invalid Certificate Transparency log URL %q", logURL)
	}
	base.Path = strings.TrimRight(base.Path, "/") + path
	base.RawQuery = query.Encode()
	base.Fragment = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("read %s from %s: %w", path, logURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCTSubmissionResponse))
	if err != nil {
		return nil, 0, err
	}
	return body, resp.StatusCode, nil
}
