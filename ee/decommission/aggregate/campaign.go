// SPDX-License-Identifier: LicenseRef-trstctl-EE

package aggregate

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"trstctl.com/trstctl/ee/pqcmigration"
	"trstctl.com/trstctl/internal/crypto"
)

type ForbiddenSuccessionAuthorityUseHook interface {
	OnForbiddenSuccessionAuthorityUse(operation string) error
}

type CampaignRequest struct {
	CampaignID                        string
	SuccessionEpochID                 string
	SupersedingSuccessionRecordDigest []byte
	SuccessionJobs                    []pqcmigration.SuccessionJob
	ForbiddenSuccessionAuthorityUse   ForbiddenSuccessionAuthorityUseHook
}

type CampaignBinding struct {
	CampaignID                        string   `json:"campaign_id"`
	SuccessionEpochID                 string   `json:"succession_epoch_id"`
	SupersedingSuccessionRecordDigest []byte   `json:"superseding_succession_record_digest"`
	SuccessionJobDigests              [][]byte `json:"succession_job_digests,omitempty"`
}

func CampaignBindingFromPQC(req CampaignRequest) (CampaignBinding, error) {
	campaignID := strings.TrimSpace(req.CampaignID)
	epochID := strings.TrimSpace(req.SuccessionEpochID)
	if campaignID == "" || epochID == "" || len(req.SupersedingSuccessionRecordDigest) == 0 {
		return CampaignBinding{}, fmt.Errorf("%w: campaign id, succession epoch id, and consumed succession record digest are required", ErrInvalidRecord)
	}
	digests := make([][]byte, 0, len(req.SuccessionJobs))
	for _, job := range req.SuccessionJobs {
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
