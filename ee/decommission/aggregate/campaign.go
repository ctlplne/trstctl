// SPDX-License-Identifier: LicenseRef-trstctl-EE

package aggregate

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

type ForbiddenSuccessionAuthorityUseHook interface {
	OnForbiddenSuccessionAuthorityUse(operation string) error
}

type CampaignRequest struct {
	CampaignID                        string
	SuccessionEpochID                 string
	SupersedingSuccessionRecordDigest []byte
	SuccessionJobs                    any
	ForbiddenSuccessionAuthorityUse   ForbiddenSuccessionAuthorityUseHook
}

type CampaignBinding struct {
	CampaignID                        string   `json:"campaign_id"`
	SuccessionEpochID                 string   `json:"succession_epoch_id"`
	SupersedingSuccessionRecordDigest []byte   `json:"superseding_succession_record_digest"`
	SuccessionJobDigests              [][]byte `json:"succession_job_digests,omitempty"`
}

// CampaignBindingFromPQC practices VDEC-claim-10: the retirement request is one of
// a plurality from a decommissioning campaign keyed to the algorithm-succession
// epoch at which the keys were superseded, and the commitment binds the epoch
// identifier and a digest of the superseding succession record.
func CampaignBindingFromPQC(req CampaignRequest) (CampaignBinding, error) {
	campaignID := strings.TrimSpace(req.CampaignID)
	epochID := strings.TrimSpace(req.SuccessionEpochID)
	if campaignID == "" || epochID == "" || len(req.SupersedingSuccessionRecordDigest) == 0 {
		return CampaignBinding{}, fmt.Errorf("%w: campaign id, succession epoch id, and consumed succession record digest are required", ErrInvalidRecord)
	}
	jobs := reflect.ValueOf(req.SuccessionJobs)
	digests := make([][]byte, 0, jobCount(jobs))
	for _, job := range jobValues(jobs) {
		raw, err := json.Marshal(job)
		if err != nil {
			return CampaignBinding{}, fmt.Errorf("aggregate decommissioning record: encode succession job digest: %w", err)
		}
		digests = append(digests, crypto.SHA256Sum(raw))
	}
	sort.Slice(digests, func(i, j int) bool { return string(digests[i]) < string(digests[j]) })
	return CampaignBinding{
		CampaignID:                        campaignID,
		SuccessionEpochID:                 epochID,
		SupersedingSuccessionRecordDigest: cloneBytes(req.SupersedingSuccessionRecordDigest),
		SuccessionJobDigests:              clone2D(digests),
	}, nil
}

func jobCount(v reflect.Value) int {
	if !v.IsValid() {
		return 0
	}
	switch v.Kind() {
	case reflect.Array, reflect.Slice:
		return v.Len()
	default:
		return 1
	}
}

func jobValues(v reflect.Value) []any {
	if !v.IsValid() {
		return nil
	}
	switch v.Kind() {
	case reflect.Array, reflect.Slice:
		out := make([]any, 0, v.Len())
		for i := 0; i < v.Len(); i++ {
			out = append(out, v.Index(i).Interface())
		}
		return out
	default:
		return []any{v.Interface()}
	}
}

func cloneCampaign(in *CampaignBinding) *CampaignBinding {
	if in == nil {
		return nil
	}
	out := *in
	out.CampaignID = strings.TrimSpace(out.CampaignID)
	out.SuccessionEpochID = strings.TrimSpace(out.SuccessionEpochID)
	out.SupersedingSuccessionRecordDigest = cloneBytes(out.SupersedingSuccessionRecordDigest)
	out.SuccessionJobDigests = clone2D(out.SuccessionJobDigests)
	sort.Slice(out.SuccessionJobDigests, func(i, j int) bool {
		return string(out.SuccessionJobDigests[i]) < string(out.SuccessionJobDigests[j])
	})
	return &out
}

func clone2D(in [][]byte) [][]byte {
	if in == nil {
		return nil
	}
	out := make([][]byte, len(in))
	for i := range in {
		out[i] = cloneBytes(in[i])
	}
	return out
}
