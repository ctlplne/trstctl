// SPDX-License-Identifier: MPL-2.0

package acme

import (
	"sort"
	"time"
)

// DomainValidationActivity is the secret-free operator view of one identifier's
// real served ACME state. Challenge tokens, account URLs, key thumbprints, and
// certificate bytes deliberately never enter this shape.
type DomainValidationActivity struct {
	OrderID             string
	Domain              string
	OrderStatus         string
	AuthorizationStatus string
	ChallengeMethods    []string
	ValidatedMethod     string
	ValidationSkipped   bool
	CreatedAt           time.Time
}

// DomainValidationActivities returns the newest real ACME authorization rows
// from the event-replayed serving view. It is a pure read: no nonce is consumed,
// no challenge is retried, and no external system is contacted.
func (s *Server) DomainValidationActivities(limit int) []DomainValidationActivity {
	if s == nil || limit <= 0 {
		return []DomainValidationActivity{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	rows := make([]DomainValidationActivity, 0, len(s.authzs))
	for _, az := range s.authzs {
		if az == nil {
			continue
		}
		row := DomainValidationActivity{
			Domain:              az.domain,
			AuthorizationStatus: az.status,
			CreatedAt:           az.createdAt,
			ChallengeMethods:    []string{},
		}
		if o := s.orders[az.orderID]; o != nil {
			row.OrderID = o.id
			row.OrderStatus = o.status
			row.ValidationSkipped = o.authMode == profileACMEAuthMode("trust_authenticated")
		}
		for _, ch := range az.challenges {
			if ch == nil {
				continue
			}
			row.ChallengeMethods = append(row.ChallengeMethods, ch.typ)
			if !row.ValidationSkipped && ch.status == statusValid && row.ValidatedMethod == "" {
				row.ValidatedMethod = ch.typ
			}
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if !rows[i].CreatedAt.Equal(rows[j].CreatedAt) {
			return rows[i].CreatedAt.After(rows[j].CreatedAt)
		}
		if rows[i].OrderID != rows[j].OrderID {
			return rows[i].OrderID > rows[j].OrderID
		}
		return rows[i].Domain < rows[j].Domain
	})
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}
