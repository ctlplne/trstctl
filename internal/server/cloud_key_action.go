// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/discovery/cloudkeys"
	"trstctl.com/trstctl/internal/discovery/cloudkeys/awsiamkeys"
	"trstctl.com/trstctl/internal/orchestrator"
)

// The control-plane executor of a cloud key replacement (M3-L4): it reopens
// the finding's source connection for the key's provider, sets the key
// Inactive at IAM, and records what IAM confirmed; a confirmed or already-gone
// key marks the finding remediated with its replacement. IAM out of reach,
// throttling or failing on its side leaves the row to retry; any other
// refusal is recorded as failed with IAM's status, because it would fail the
// same way every time.
func (d *issuanceDispatcher) handleCloudKeyAction(ctx context.Context, m orchestrator.Message) error {
	if d.store == nil || d.orch == nil {
		return errors.New("server: cloud key actions are not configured")
	}
	var in orchestrator.CloudKeyActionIntent
	if err := json.Unmarshal(m.Payload, &in); err != nil || strings.TrimSpace(in.RequestID) == "" || strings.TrimSpace(in.SourceID) == "" {
		return orchestrator.DefiniteNoEffect(errors.New("server: cloud key action row is malformed"))
	}
	now := time.Now().UTC()
	fail := func(detail string) error {
		if err := d.orch.RecordCloudKeyAction(ctx, m.TenantID, in, orchestrator.OAuthActionFailed, detail, now); err != nil {
			return err
		}
		return orchestrator.DefiniteNoEffect(errors.New("server: cloud key action failed: " + detail))
	}
	if in.Provider != cloudkeys.ProviderAWSIAM || in.Action != orchestrator.CloudKeyActionDeactivate {
		return fail("only an aws-iam key can be deactivated")
	}
	source, err := d.store.GetDiscoverySource(ctx, m.TenantID, in.SourceID)
	if err != nil {
		return fail("the discovery source that found the key is gone")
	}
	var cfg cloudCertificateDiscoveryConfig
	if err := json.Unmarshal(source.Config, &cfg); err != nil {
		return fail("the discovery source's configuration cannot be read")
	}
	// A source may read more than one AWS account at the same IAM host; a key
	// ID belongs to one account, and the others answer NoSuchEntity (404).
	matched := 0
	for _, provider := range cfg.Providers {
		if strings.TrimSpace(provider.Provider) != cloudkeys.ProviderAWSIAM {
			continue
		}
		if _, host, err := awsIAMEndpoint(provider); err != nil || host != in.Host {
			continue
		}
		matched++
		reader, _, err := awsIAMReader(ctx, provider, d.egress)
		if err != nil {
			return fail("open the IAM connection: " + err.Error())
		}
		err = reader.DeactivateKey(ctx, in.User, in.AccessKeyID)
		var status *awsiamkeys.StatusError
		switch {
		case err == nil:
			return d.orch.RecordCloudKeyAction(ctx, m.TenantID, in, orchestrator.OAuthActionConfirmed,
				"IAM set the key Inactive; replaced by short-lived credentials from "+in.Replacement(), now)
		case errors.As(err, &status) && status.Status == http.StatusNotFound:
			continue // not this account's key
		case errors.As(err, &status) && status.Status != http.StatusTooManyRequests && status.Status < 500:
			return fail(fmt.Sprintf("IAM refused UpdateAccessKey: status %d", status.Status))
		default:
			return err // IAM out of reach, throttling or failing: retry
		}
	}
	if matched == 0 {
		return fail("the discovery source no longer has an aws-iam connection at " + in.Host)
	}
	return d.orch.RecordCloudKeyAction(ctx, m.TenantID, in, orchestrator.OAuthActionAlreadyAbsent,
		"IAM no longer has the key or its user", now)
}
