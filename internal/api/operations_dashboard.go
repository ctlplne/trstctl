// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"sort"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/backup"
)

// The operations dashboard (A246): backup freshness, restore proof, queue lag,
// signer readiness, data freshness and dependency health in one read, each
// with the numbers behind its state so they can be checked against an
// independent read of the same source.

const (
	dashOK       = "ok"
	dashWarning  = "warning"
	dashCritical = "critical"
	dashUnknown  = "unknown"
)

var dashboardStates = []string{dashOK, dashWarning, dashCritical, dashUnknown}

// OperationsDependency is one readiness probe's verdict.
type OperationsDependency struct {
	Name    string `json:"name"`
	Healthy bool   `json:"healthy"`
	Detail  string `json:"detail,omitempty"`
}

// OperationsHealth is what the server measures for the dashboard: the event
// log's head, the projection's applied and failed sequences, and every
// readiness probe.
type OperationsHealth struct {
	EventHead         uint64
	ProjectionApplied uint64
	ProjectionFailed  uint64
	Dependencies      []OperationsDependency
}

// OperationsHealthProvider measures the deployment for the dashboard.
type OperationsHealthProvider interface {
	OperationsHealth(ctx context.Context) (OperationsHealth, error)
}

// WithOperationsHealth wires the dashboard's measurements (A246).
func WithOperationsHealth(provider OperationsHealthProvider) Option {
	return func(c *config) { c.operationsHealth = provider }
}

type dashboardBackup struct {
	State          string `json:"state"`
	Detail         string `json:"detail"`
	Configured     bool   `json:"configured"`
	Verified       bool   `json:"verified"`
	LastBackupAt   string `json:"last_backup_at,omitempty"`
	LastVerifiedAt string `json:"last_verified_at,omitempty"`
	// AgeSeconds is how long ago the newest backup was taken. Verification
	// re-hashes the backup on every read, so its time says nothing about age.
	AgeSeconds *int64 `json:"age_seconds,omitempty"`
}

type dashboardRestore struct {
	State       string `json:"state"`
	Detail      string `json:"detail"`
	Outcome     string `json:"outcome,omitempty"`
	CompletedAt string `json:"completed_at,omitempty"`
	RPOSeconds  int64  `json:"rpo_seconds,omitempty"`
	RTOSeconds  int64  `json:"rto_seconds,omitempty"`
}

type dashboardQueues struct {
	State                string `json:"state"`
	Detail               string `json:"detail"`
	Pending              int    `json:"pending"`
	Processing           int    `json:"processing"`
	Stranded             int    `json:"stranded"`
	Failed               int    `json:"failed"`
	OldestPendingSeconds *int64 `json:"oldest_pending_seconds,omitempty"`
}

type dashboardSigner struct {
	State   string `json:"state"`
	Detail  string `json:"detail"`
	Healthy bool   `json:"healthy"`
}

type dashboardFreshness struct {
	State             string `json:"state"`
	Detail            string `json:"detail"`
	EventHead         uint64 `json:"event_head"`
	ProjectionApplied uint64 `json:"projection_applied"`
	LagEvents         uint64 `json:"lag_events"`
	FailedSequence    uint64 `json:"failed_sequence,omitempty"`
}

type operationsDashboard struct {
	GeneratedAt   time.Time              `json:"generated_at"`
	Backup        dashboardBackup        `json:"backup"`
	RestoreProof  dashboardRestore       `json:"restore_proof"`
	Queues        dashboardQueues        `json:"queues"`
	Signer        dashboardSigner        `json:"signer"`
	DataFreshness dashboardFreshness     `json:"data_freshness"`
	Dependencies  []OperationsDependency `json:"dependencies"`
}

// Thresholds a deployment is held to: a backup taken within a day, no
// command waiting past a quarter hour, a projection within a thousand events
// of the log.
const (
	backupFreshFor       = backup.FreshFor
	backupStaleAfter     = 72 * time.Hour
	queueWaitWarning     = 15 * time.Minute
	queueWaitCritical    = time.Hour
	projectionLagWarning = 1000
)

func classifyBackup(dr DRPosture, now time.Time) dashboardBackup {
	out := dashboardBackup{Configured: dr.BackupConfigured, Verified: dr.Verified, LastBackupAt: dr.LastBackupAt, LastVerifiedAt: dr.LastVerifiedAt}
	if takenAt, err := time.Parse(time.RFC3339, dr.LastBackupAt); err == nil {
		age := int64(now.Sub(takenAt).Seconds())
		out.AgeSeconds = &age
	}
	switch {
	case !dr.BackupConfigured:
		out.State, out.Detail = dashUnknown, "no backup directory is configured; backups made outside this control plane are not seen"
	case dr.LastVerifiedAt == "":
		out.State, out.Detail = dashCritical, "the backup directory is configured and could not be read"
	case !dr.Verified:
		out.State, out.Detail = dashCritical, "the newest backup did not verify: a required artifact's bytes no longer match"
	case out.AgeSeconds == nil:
		out.State, out.Detail = dashWarning, "the newest backup's manifest records no time it was taken"
	case time.Duration(*out.AgeSeconds)*time.Second > backupStaleAfter:
		out.State, out.Detail = dashCritical, "the newest backup is more than three days old"
	case time.Duration(*out.AgeSeconds)*time.Second > backupFreshFor:
		out.State, out.Detail = dashWarning, "the newest backup is more than a day old"
	case len(dr.Failures) > 0:
		out.State, out.Detail = dashWarning, "the newest backup verifies, and an optional artifact in it does not"
	default:
		out.State, out.Detail = dashOK, "the newest backup is less than a day old and verifies"
	}
	return out
}

func classifyRestore(dr DRPosture) dashboardRestore {
	if dr.LastDrill == nil {
		return dashboardRestore{State: dashWarning, Detail: "no restore drill has run: the backup has never been proven to restore"}
	}
	d := dr.LastDrill
	out := dashboardRestore{Outcome: d.Outcome, CompletedAt: d.CompletedAt, RPOSeconds: d.RPOSeconds, RTOSeconds: d.RTOSeconds}
	switch d.Outcome {
	case "restored":
		out.State, out.Detail = dashOK, "the last drill restored the backup into an isolated deployment"
	case "failed":
		out.State, out.Detail = dashCritical, "the last restore drill failed"
	default:
		out.State, out.Detail = dashWarning, "the last restore drill was skipped"
	}
	return out
}

func classifyQueues(pending, processing, stranded, failed int, oldest *time.Time, now time.Time) dashboardQueues {
	out := dashboardQueues{Pending: pending, Processing: processing, Stranded: stranded, Failed: failed}
	wait := time.Duration(0)
	if oldest != nil {
		seconds := int64(now.Sub(*oldest).Seconds())
		out.OldestPendingSeconds = &seconds
		wait = now.Sub(*oldest)
	}
	switch {
	case wait > queueWaitCritical || stranded > 0:
		out.State, out.Detail = dashCritical, "a command has waited over an hour, or a worker's lease ran out on one"
	case wait > queueWaitWarning || failed > 0:
		out.State, out.Detail = dashWarning, "a command has waited over fifteen minutes, or some failed for good"
	default:
		out.State, out.Detail = dashOK, "the queue is draining"
	}
	return out
}

func classifyFreshness(h OperationsHealth) dashboardFreshness {
	out := dashboardFreshness{EventHead: h.EventHead, ProjectionApplied: h.ProjectionApplied, FailedSequence: h.ProjectionFailed}
	if h.EventHead > h.ProjectionApplied {
		out.LagEvents = h.EventHead - h.ProjectionApplied
	}
	switch {
	case h.ProjectionFailed > 0:
		out.State, out.Detail = dashCritical, "the read model stopped at an event it could not apply"
	case out.LagEvents > projectionLagWarning:
		out.State, out.Detail = dashWarning, "the read model is more than a thousand events behind the log"
	default:
		out.State, out.Detail = dashOK, "the read model is current with the log"
	}
	return out
}

func (a *API) getOperationsDashboard(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	now := time.Now().UTC()
	out := operationsDashboard{GeneratedAt: now, Dependencies: []OperationsDependency{}}
	dr, err := a.drPostureView(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	out.Backup, out.RestoreProof = classifyBackup(dr, now), classifyRestore(dr)
	stats, err := a.store.OutboxQueueStats(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	out.Queues = classifyQueues(stats.Pending, stats.Processing, stats.Stranded, stats.Failed, stats.OldestPendingAt, now)
	out.Signer = dashboardSigner{State: dashUnknown, Detail: "the signer's readiness is not measured here"}
	out.DataFreshness = dashboardFreshness{State: dashUnknown, Detail: "the read model's position is not measured here"}
	if a.operationsHealth != nil {
		health, err := a.operationsHealth.OperationsHealth(r.Context())
		if err != nil {
			a.writeError(w, err)
			return
		}
		out.DataFreshness = classifyFreshness(health)
		out.Dependencies = append(out.Dependencies, health.Dependencies...)
		sort.Slice(out.Dependencies, func(i, j int) bool { return out.Dependencies[i].Name < out.Dependencies[j].Name })
		for _, dep := range health.Dependencies {
			if dep.Name != "signer" {
				continue
			}
			out.Signer = dashboardSigner{State: dashOK, Healthy: true, Detail: "the signer answers its readiness probe"}
			if !dep.Healthy {
				out.Signer = dashboardSigner{State: dashCritical, Detail: dep.Detail}
			}
		}
	}
	a.writeJSON(w, http.StatusOK, out)
}

func operationsDashboardRoutes(a *API) []route {
	return []route{
		{method: "GET", path: "/api/v1/operations/dashboard", opID: "getOperationsDashboard",
			summary: "Show backup freshness, restore proof, queue lag, signer readiness, data freshness and dependency health, each with the numbers behind its state",
			handler: a.getOperationsDashboard, resSchema: "OperationsDashboard", successCode: "200", perm: authz.AccessRead},
	}
}

func operationsDashboardSchemas() map[string]*Schema {
	state := func() *Schema { return &Schema{Type: "string", Enum: dashboardStates} }
	integer := func() *Schema { return &Schema{Type: "integer"} }
	boolean := func() *Schema { return &Schema{Type: "boolean"} }
	return map[string]*Schema{
		"OperationsDashboard": object(map[string]*Schema{
			"generated_at": timestamp(),
			"backup": object(map[string]*Schema{"state": state(), "detail": str(), "configured": boolean(), "verified": boolean(),
				"last_backup_at": str(), "last_verified_at": str(), "age_seconds": integer()}, "state", "detail", "configured", "verified"),
			"restore_proof": object(map[string]*Schema{"state": state(), "detail": str(), "outcome": str(), "completed_at": str(),
				"rpo_seconds": integer(), "rto_seconds": integer()}, "state", "detail"),
			"queues": object(map[string]*Schema{"state": state(), "detail": str(), "pending": integer(), "processing": integer(),
				"stranded": integer(), "failed": integer(), "oldest_pending_seconds": integer()}, "state", "detail", "pending", "processing", "stranded", "failed"),
			"signer": object(map[string]*Schema{"state": state(), "detail": str(), "healthy": boolean()}, "state", "detail", "healthy"),
			"data_freshness": object(map[string]*Schema{"state": state(), "detail": str(), "event_head": integer(), "projection_applied": integer(),
				"lag_events": integer(), "failed_sequence": integer()}, "state", "detail", "event_head", "projection_applied", "lag_events"),
			"dependencies": {Type: "array", Items: object(map[string]*Schema{"name": str(), "healthy": boolean(), "detail": str()}, "name", "healthy")},
		}, "generated_at", "backup", "restore_proof", "queues", "signer", "data_freshness", "dependencies"),
	}
}
