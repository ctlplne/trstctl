// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type awsHoneyScanCommand struct {
	ID     string `json:"id"`
	Region string `json:"region"`
	Cycle  int64  `json:"cycle"`
	Page   int    `json:"page"`
}

// CloudTrail delivery is delayed. Continue scanning after IAM key deletion so
// use just before retirement is not silently lost from incident history.
const awsHoneyPostRetirementObservation = 72 * time.Hour

func awsHoneyScanEventID(tenantID string, command awsHoneyScanCommand) string {
	material := []byte(fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%d", tenantID, command.ID, command.Region, command.Cycle, command.Page))
	return "honey-aws-scan:" + crypto.SHA256Hex(material)
}

// scanAWSHoneyToken is the only path that calls CloudTrail. Its request is a
// tenant-scoped outbox row created by an event projection, never by an HTTP
// handler. Each read-only page becomes one immutable event before the next page
// is queued, so a crash or overlapping lookup cannot lose or duplicate alerts.
func (d *secretIntegrationOutboxDispatcher) scanAWSHoneyToken(ctx context.Context, m orchestrator.Message) error {
	if d.store == nil || d.log == nil || d.awsHoneyAccounts == nil {
		return errors.New("server: AWS honeytoken monitor is not configured")
	}
	var command awsHoneyScanCommand
	if json.Unmarshal(m.Payload, &command) != nil || command.ID == "" || command.Region == "" || command.Cycle < 0 || command.Page < 0 ||
		m.IdempotencyKey != store.AWSHoneyScanKey(command.ID, command.Region, command.Cycle, command.Page) {
		return errors.New("server: AWS honeytoken scan command is invalid")
	}
	honey, err := d.store.GetHoneyToken(ctx, m.TenantID, command.ID)
	if err != nil {
		return err
	}
	if honey.Kind != "aws" || honey.AWSLeaseID == "" {
		return errors.New("server: AWS honeytoken scan points to a foreign decoy")
	}
	account := d.awsHoneyAccounts.Account(m.TenantID, honey.AWSAccountConfigID)
	if account == nil || account.cfg.AccountID != honey.AWSAccountID {
		return errors.New("server: AWS honeytoken account attachment changed or disappeared")
	}
	if !account.hasRegion(command.Region) {
		return errors.New("server: AWS honeytoken region is no longer monitored by its account attachment")
	}
	lease, err := d.store.GetDynamicSecretLease(ctx, m.TenantID, honey.AWSLeaseID)
	if err != nil {
		return err
	}
	if lease.Provider != account.Name() || lease.Role != "decoy" {
		return errors.New("server: AWS honeytoken IAM lease is outside its configured account")
	}
	if lease.State == store.DynamicSecretLeaseRevoked && lease.RevocationStatus == store.DynamicSecretRevocationCompleted &&
		lease.RevocationCompletedAt != nil && time.Since(*lease.RevocationCompletedAt) >= awsHoneyPostRetirementObservation {
		return nil
	}
	if lease.State != store.DynamicSecretLeaseActive && lease.State != store.DynamicSecretLeaseRevoked {
		return orchestrator.DeferDelivery(errors.New("AWS honeytoken IAM issuance is not yet active"))
	}
	accountID, decoyID, keyID, ownerTag, ok := dynsecret.AWSHoneyReference(lease.BackendRef)
	if !ok || accountID != honey.AWSAccountID || decoyID != honey.AWSLeaseID || keyID != honey.AWSAccessKeyID || ownerTag != account.ownerTag(decoyID) {
		return errors.New("server: AWS honeytoken scan lease identity mismatch")
	}
	scan, err := d.store.GetAWSHoneyScan(ctx, m.TenantID, command.ID, command.Region)
	if err != nil {
		return err
	}
	if scan.Cycle > command.Cycle || (scan.Cycle == command.Cycle && scan.Page > command.Page) {
		return nil // already projected and successor queued
	}
	if scan.Cycle != command.Cycle || scan.Page != command.Page {
		return errors.New("server: AWS honeytoken scan command is ahead of its projected cursor")
	}
	eventID := awsHoneyScanEventID(m.TenantID, command)
	if retained, found, err := d.log.EventByID(ctx, eventID); err != nil {
		return err
	} else if found {
		if retained.Type != projections.EventAWSHoneyScanPage || retained.TenantID != m.TenantID || retained.SchemaVersion != 1 {
			return errors.New("server: AWS honeytoken scan event identity collided")
		}
		return projections.New(d.store).Apply(ctx, retained)
	}
	when := time.Now().UTC()
	start, end, requestToken := scan.Watermark.Add(-10*time.Minute), when, scan.NextToken
	var gapSince *time.Time
	if command.Page > 0 {
		if scan.WindowStart == nil || scan.WindowEnd == nil {
			return errors.New("server: AWS honeytoken CloudTrail page lost its fixed time window")
		}
		start, end = *scan.WindowStart, *scan.WindowEnd
	} else if floor := when.Add(-90 * 24 * time.Hour); start.Before(floor) {
		gap := scan.Watermark
		gapSince = &gap
		start = floor
	}
	if !start.Before(end) || end.Sub(start) > 90*24*time.Hour {
		return errors.New("server: AWS honeytoken CloudTrail scan window is invalid")
	}
	resumeAt, permit, err := d.store.AcquireAWSHoneyCloudTrailPermit(ctx, m.TenantID, account.cfg.AccountID, command.Region)
	if err != nil {
		return err
	}
	if !permit {
		return orchestrator.DeferDeliveryUntil(errors.New("AWS CloudTrail account and Region quota is occupied"), resumeAt)
	}
	client, err := account.openCloudTrail(ctx, command.Region)
	if err != nil {
		return err
	}
	defer client.Close()
	observed, nextToken, err := client.LookupManagementPage(ctx, honey.AWSAccessKeyID, start, end, requestToken)
	if err != nil {
		return err
	}
	if nextToken != "" && nextToken == requestToken {
		return errors.New("server: AWS CloudTrail repeated a page token without progress")
	}
	page := store.AWSHoneyScanPage{
		HoneyID: command.ID, Region: command.Region, Cycle: command.Cycle,
		Page: command.Page, WindowStart: start, WindowEnd: end,
		RequestToken: requestToken, NextToken: nextToken, GapSince: gapSince,
		Uses: make([]store.AWSHoneyUse, 0, len(observed)),
	}
	for _, use := range observed {
		page.Uses = append(page.Uses, store.AWSHoneyUse{
			EventID: use.EventID, Region: use.Region, EventSource: use.EventSource,
			EventName: use.EventName, SourceIPAddress: use.SourceIPAddress,
			UserAgent: use.UserAgent, ErrorCode: use.ErrorCode,
			EventTime: use.EventTime, DetectedAt: when,
		})
	}
	data, err := json.Marshal(page)
	if err != nil {
		return err
	}
	event := events.Event{ID: eventID, Type: projections.EventAWSHoneyScanPage,
		TenantID: m.TenantID, SchemaVersion: 1, Data: data}
	committed, err := d.log.Append(ctx, event)
	if err != nil {
		return err
	}
	if committed.Type != event.Type || committed.TenantID != event.TenantID ||
		committed.SchemaVersion != event.SchemaVersion || !bytes.Equal(committed.Data, event.Data) {
		return errors.New("server: AWS honeytoken scan event differs from retained authority")
	}
	return projections.New(d.store).Apply(ctx, committed)
}
