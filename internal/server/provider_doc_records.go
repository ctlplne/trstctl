// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/docsys"
	"trstctl.com/trstctl/internal/docsys/hudu"
	"trstctl.com/trstctl/internal/docsys/itglue"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// handleDocRecord keeps a customer's documentation record current (MSP-14):
// it renders the customer's own certificate inventory, and when that differs
// from what was last written (or the record was never written, failed, or the
// customer moved to another organization), writes it to the customer's
// record under the mapped organization — updating it in place, creating it
// when there is none (reusing the one of the same title under that
// organization after a lost answer), or creating it again when it was
// deleted there — and records the outcome.
func (d *issuanceDispatcher) handleDocRecord(ctx context.Context, m orchestrator.Message) error {
	var req orchestrator.DocRecordRequest
	if err := json.Unmarshal(m.Payload, &req); err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: decode documentation record sync: %w", err))
	}
	if m.IdempotencyKey != orchestrator.DocRecordKey(req.TargetID, req.Bucket) {
		return orchestrator.DefiniteNoEffect(errors.New("server: documentation record key does not name its target and interval"))
	}
	target, ok := d.billingSync.Target(req.TargetID)
	if !ok || !target.IsDocumentation() {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: documentation target %q is no longer configured", req.TargetID))
	}
	if d.store == nil || d.orch == nil {
		return errors.New("server: documentation records need the store and the orchestrator")
	}
	org, mapped, err := d.store.BillingCompanyFor(ctx, m.TenantID, target.ID)
	if err != nil {
		return err
	}
	if !mapped {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: the customer is no longer mapped in documentation target %q", target.ID))
	}
	certs, total, err := d.store.DocRecordCertificates(ctx, m.TenantID, docsys.MaxRows)
	if err != nil {
		return err
	}
	name := m.TenantID
	if tenant, err := d.store.GetTenant(ctx, m.TenantID); err == nil && strings.TrimSpace(tenant.Name) != "" {
		name = tenant.Name
	}
	rows := make([]docsys.Certificate, 0, len(certs))
	for _, c := range certs {
		rows = append(rows, docsys.Certificate{Subject: c.Subject, SANs: c.SANs, Issuer: c.Issuer, Serial: c.Serial, NotAfter: c.NotAfter, Location: c.Location})
	}
	content := docsys.Render(name, rows, total, docConsoleURL(target))
	cur, found, err := d.store.DocRecordFor(ctx, m.TenantID, target.ID)
	if err != nil {
		return err
	}
	sameOrg := found && strings.EqualFold(cur.OrgID, org) && cur.RecordID != ""
	if sameOrg && cur.Status == store.DocRecordSynced && cur.Digest == content.Digest {
		return nil
	}
	recordID := ""
	err = d.withDocClient(target, func(c docsys.Client) error {
		if sameOrg {
			err := c.Update(ctx, org, cur.RecordID, content)
			switch {
			case err == nil:
				recordID = cur.RecordID
				return nil
			case !errors.Is(err, docsys.ErrRecordGone):
				return err
			}
		}
		existing, exists, err := c.Find(ctx, org, content.Title)
		if err != nil {
			return err
		}
		if exists {
			if err := c.Update(ctx, org, existing, content); err != nil {
				return err
			}
			recordID = existing
			return nil
		}
		recordID, err = c.Create(ctx, org, content)
		return err
	})
	switch {
	case err == nil:
		return d.orch.RecordDocRecord(ctx, m.TenantID, projections.DocRecordEvent{TargetID: target.ID, OrgID: org, RecordID: recordID,
			Digest: content.Digest, Certificates: content.Count, NextExpiry: content.NextExpiry, OK: true})
	case errors.Is(err, docsys.ErrBeforeWrite), errors.Is(err, docsys.ErrRefused), orchestrator.IsDefiniteNoEffect(err):
		return d.orch.RecordDocRecord(ctx, m.TenantID, projections.DocRecordEvent{TargetID: target.ID, OrgID: org, Reason: err.Error()})
	default:
		return err
	}
}

// docConsoleURL is the console base URL a record links back to.
func docConsoleURL(target config.ProviderBillingTarget) string {
	switch {
	case target.ITGlue != nil:
		return target.ITGlue.ConsoleURL
	case target.Hudu != nil:
		return target.Hudu.ConsoleURL
	}
	return ""
}

// withDocClient resolves a documentation target's credentials for one
// delivery, hands fn its client, and wipes the credentials afterwards.
func (d *issuanceDispatcher) withDocClient(target config.ProviderBillingTarget, fn func(docsys.Client) error) error {
	client, err := d.billingSyncHTTPClient(target)
	if err != nil {
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: documentation target endpoint rejected: %w", err))
	}
	switch {
	case target.Type == "itglue" && target.ITGlue != nil:
		g := target.ITGlue
		key, err := resolveDeploymentCredentialRef(g.APIKeyRef)
		if err != nil {
			return orchestrator.DefiniteNoEffect(errors.New("server: resolve the itglue target's api_key_ref"))
		}
		defer key.Destroy()
		c, err := itglue.New(itglue.Config{BaseURL: target.Endpoint, FlexibleAssetTypeID: g.FlexibleAssetTypeID,
			Traits: itglue.Traits{Title: g.Traits.Title, Inventory: g.Traits.Inventory, NextExpiry: g.Traits.NextExpiry, Count: g.Traits.Count,
				Link: g.Traits.Link}}, client, itglue.Credentials{APIKey: key.Bytes()})
		if err != nil {
			return orchestrator.DefiniteNoEffect(err)
		}
		return fn(c)
	case target.Type == "hudu" && target.Hudu != nil:
		hu := target.Hudu
		key, err := resolveDeploymentCredentialRef(hu.APIKeyRef)
		if err != nil {
			return orchestrator.DefiniteNoEffect(errors.New("server: resolve the hudu target's api_key_ref"))
		}
		defer key.Destroy()
		c, err := hudu.New(hudu.Config{BaseURL: target.Endpoint, AssetLayoutID: hu.AssetLayoutID,
			Fields: hudu.Fields{Inventory: hu.Fields.Inventory, NextExpiry: hu.Fields.NextExpiry, Count: hu.Fields.Count, Link: hu.Fields.Link}},
			client, hudu.Credentials{APIKey: key.Bytes()})
		if err != nil {
			return orchestrator.DefiniteNoEffect(err)
		}
		return fn(c)
	default:
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: documentation target %q has no %s settings", target.ID, target.Type))
	}
}
