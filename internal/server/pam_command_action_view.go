// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
)

func (s *pamService) ListPAMCommandActions(ctx context.Context, tenantID, sessionID string, limit int, cursor string) ([]api.PAMCommandAction, string, error) {
	if !validUUID(sessionID) {
		return nil, "", api.ErrPAMInvalid
	}
	if _, err := s.store.GetPAMSession(ctx, tenantID, sessionID); err != nil {
		return nil, "", err
	}
	if limit < 1 || limit > 100 {
		return nil, "", fmt.Errorf("%w: page size must be 1-100", api.ErrPAMInvalid)
	}
	var before *time.Time
	beforeID := ""
	if cursor != "" {
		if len(cursor) > 256 {
			return nil, "", api.ErrPAMInvalid
		}
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil {
			return nil, "", api.ErrPAMInvalid
		}
		parts := strings.Split(string(raw), "|")
		if len(parts) != 2 {
			return nil, "", api.ErrPAMInvalid
		}
		at, err := time.Parse(time.RFC3339Nano, parts[0])
		if err != nil {
			return nil, "", api.ErrPAMInvalid
		}
		id, err := uuid.Parse(parts[1])
		if err != nil || id == uuid.Nil || id.String() != parts[1] {
			return nil, "", api.ErrPAMInvalid
		}
		before = &at
		beforeID = parts[1]
	}
	rows, err := s.store.ListPAMCommandActions(ctx, tenantID, sessionID, limit+1, before, beforeID)
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(rows) > limit {
		rows = rows[:limit]
		last := rows[len(rows)-1]
		next = base64.RawURLEncoding.EncodeToString([]byte(last.ObservedAt.UTC().Format(time.RFC3339Nano) + "|" + last.ID))
	}
	items := make([]api.PAMCommandAction, 0, len(rows))
	for _, r := range rows {
		effective := r.Status
		if effective == "pending" && r.ReviewExpiresAt != nil && !s.clock().Before(*r.ReviewExpiresAt) {
			effective = "review_deadline_elapsed"
		}
		items = append(items, api.PAMCommandAction{Decision: r.Decision, SourceEventID: r.SourceEventID, ApprovalRequestID: r.ApprovalRequestID, ApprovalIntentDigest: r.ApprovalIntentDigest, EffectiveStatus: effective})
	}
	return items, next, nil
}

func (s *Server) ListPAMCommandActions(ctx context.Context, tenantID, sessionID string, limit int, cursor string) ([]api.PAMCommandAction, string, error) {
	if s.pam == nil {
		return nil, "", api.ErrPAMUnavailable
	}
	return s.pam.ListPAMCommandActions(ctx, tenantID, sessionID, limit, cursor)
}
