// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/store"
)

// LifecycleAutomationPlan is the server-owned, effect-free explanation of the
// already-running F6 scheduler. It performs tenant-scoped reads only.
func (s *Server) LifecycleAutomationPlan(ctx context.Context, tenantID string, at time.Time) (api.LifecycleAutomationPlan, error) {
	at = at.UTC()
	interval := s.lifecycleInterval
	if interval <= 0 {
		interval = defaultLifecycleSchedulerInterval
	}
	status := "running"
	maintenanceStatus := "open"
	deferral := s.maintenanceWindows.DeferralReason(at)
	var nextOpen *time.Time
	if s.lifecycleRenewBefore <= 0 || s.store == nil || s.orch == nil {
		status = "disabled"
	} else if deferral != "" {
		status = "deferred"
		maintenanceStatus = "closed"
		next := s.maintenanceWindows.NextOpen(at)
		if !next.IsZero() {
			next = next.UTC()
			nextOpen = &next
		}
	}

	plan := api.LifecycleAutomationPlan{
		Capability:  "lifecycle_automation",
		Ready:       status != "disabled",
		GeneratedAt: at,
		Scheduler: api.LifecycleAutomationScheduler{
			Status: status, RenewBefore: s.lifecycleRenewBefore.String(), RenewBeforeSeconds: int64(s.lifecycleRenewBefore.Seconds()),
			AlertBefore: s.lifecycleAlertBefore.String(), AlertBeforeSeconds: int64(s.lifecycleAlertBefore.Seconds()),
			Interval: interval.String(), IntervalSeconds: int64(interval.Seconds()), ARIFirst: true,
			MaintenanceWindowStatus: maintenanceStatus, MaintenanceDeferral: deferral, NextOpen: nextOpen,
		},
		Items: []api.LifecycleAutomationItem{},
		Controls: []api.LifecycleAutomationControl{
			{Action: "start", State: "available", Detail: "Review and queue one due renewal through the normal identity transition."},
			{Action: "pause", State: "configuration_only", Detail: "Maintenance windows pause new scheduler starts; changing them is an operator configuration action."},
			{Action: "resume", State: "automatic", Detail: "Deferred starts resume automatically when the next maintenance window opens."},
			{Action: "retry", State: "conditional", Detail: "A failed renewal can be reviewed as a new attempt once its earlier renewal job is terminal."},
			{Action: "cancel", State: "unavailable_after_enqueue", Detail: "Canceling renewal while keeping the identity active is unavailable. Revocation or retirement stops queued issuance retries after any live worker attempt ends or expires; completed external effects are retained."},
			{Action: "rollback", State: "conditional", Detail: "Use connector rollback only when a deployed predecessor and a connector-backed rollback procedure exist."},
		},
		PreviewWrites:          []string{},
		PreviewExternalEffects: []string{},
		ExecutionWrites: []string{
			"Append the reviewed identity.renewing event.",
			"Enqueue ca.renew in the same transaction; later delivery and rotation events become immutable evidence.",
		},
		ExecutionEffects: []string{
			"The outbox worker asks the CA for a successor credential and, when bound, asks the connector to deploy it.",
		},
		VerificationSteps: []string{
			"Confirm the identity reaches deployed or renewal_failed.",
			"Confirm the rotation run and connector delivery receipts name the successor and rollback reference.",
			"Confirm the same Idempotency-Key returns the original result instead of issuing again.",
		},
	}
	if s.store == nil {
		return plan, nil
	}

	rows, err := s.store.ListLifecycleAutomationInventory(ctx, tenantID, 500)
	if err != nil {
		return api.LifecycleAutomationPlan{}, err
	}
	outbox, err := s.store.GetLifecycleAutomationOutboxSummary(ctx, tenantID)
	if err != nil {
		return api.LifecycleAutomationPlan{}, err
	}
	plan.Summary.Monitored = len(rows)
	plan.Summary.OutboxPending = outbox.Pending
	plan.Summary.OutboxProcessing = outbox.Processing
	plan.Summary.OutboxFailed = outbox.Failed
	cutoff := at.Add(s.lifecycleRenewBefore)
	for _, row := range rows {
		reason, due := lifecycleRenewalReason(store.Certificate{NotBefore: row.CertificateStart, NotAfter: row.CertificateEnd, ValidityAnchor: row.CertificateValidityAnchor}, at, cutoff)
		source := "not_due"
		explanation := "No renewal is due yet."
		switch {
		case strings.HasPrefix(reason, lifecycleARIRenewalReasonPrefix):
			source = "ari"
			explanation = "The CA renewal window is open."
		case strings.HasPrefix(reason, lifecycleFixedRenewalReasonPrefix):
			source = "fixed_deadline"
			explanation = "The configured renewal deadline has arrived."
		}
		blockers := []string{}
		if row.IdentityStatus == "renewing" || row.PendingRenewal {
			due = false
			source = "in_flight"
			explanation = "Renewal is already queued or running."
			blockers = append(blockers, "The existing renewal is still queued or running; follow its retry evidence before starting another renewal.")
		}
		if deferral != "" && due {
			blockers = append(blockers, deferral)
		}
		if row.IdentityStatus == "renewal_failed" {
			plan.Summary.RenewalFailed++
		}
		if due {
			plan.Summary.DueNow++
		}
		plan.Items = append(plan.Items, api.LifecycleAutomationItem{
			IdentityID: row.IdentityID, IdentityName: row.IdentityName, IdentityStatus: row.IdentityStatus,
			OwnerID: row.OwnerID, OwnerName: row.OwnerName, CertificateID: row.CertificateID,
			NotAfter: row.CertificateEnd, Due: due, RenewalSource: source, Reason: explanation,
			LatestRunID: row.LatestRunID, LatestRunStatus: row.LatestRunStatus,
			RollbackRef: row.RollbackRef, Blockers: blockers,
		})
	}
	return plan, nil
}
