// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// EventListenerSessionsObserved records a host agent's count, right after a
// verified deploy or renewal, of the established connections on the
// listener's port and how many a process older than the deploy holds
// (A245-L2). The revocation report reads it for whether the sessions opened
// with a replaced certificate are gone.
const EventListenerSessionsObserved = "connector.listener_sessions.observed"

// ListenerSessionsObserved is the payload of
// connector.listener_sessions.observed.
type ListenerSessionsObserved struct {
	ID            string  `json:"id"`
	IdentityID    *string `json:"identity_id,omitempty"`
	TargetID      string  `json:"target_id"`
	Target        string  `json:"target"`
	Fingerprint   string  `json:"fingerprint"`
	Port          int     `json:"port"`
	Established   int     `json:"established"`
	HeldByOlder   int     `json:"held_by_older"`
	Unattributed  int     `json:"unattributed"`
	SinceUnix     int64   `json:"since_unix"`
	CheckedAtUnix int64   `json:"checked_at_unix"`
}

// ValidateListenerSessionsObserved checks the payload's closed shape.
func ValidateListenerSessionsObserved(o ListenerSessionsObserved) error {
	if o.ID == "" || o.TargetID == "" || o.Target == "" || o.Fingerprint == "" || o.Port <= 0 || o.Port > 65535 ||
		o.Established < 0 || o.HeldByOlder < 0 || o.Unattributed < 0 || o.HeldByOlder+o.Unattributed > o.Established ||
		o.SinceUnix <= 0 || o.SinceUnix > o.CheckedAtUnix {
		return errors.New("projections: a listener session count names its target, certificate and port, with counts that hold together")
	}
	return nil
}

func init() {
	knownSchemaVersions[EventListenerSessionsObserved] = map[int]bool{1: true}
}

func (p *Projector) applyListenerSessionsTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	if e.Type != EventListenerSessionsObserved {
		return false, nil
	}
	var o ListenerSessionsObserved
	if err := json.Unmarshal(e.Data, &o); err != nil {
		return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
	}
	if err := ValidateListenerSessionsObserved(o); err != nil {
		return true, err
	}
	return true, p.store.ApplyListenerSessionsObservedTx(ctx, tx, e.TenantID, store.ListenerSessionObservation{
		ID: o.ID, IdentityID: o.IdentityID, TargetID: o.TargetID, Target: o.Target, Fingerprint: o.Fingerprint,
		Port: o.Port, Established: o.Established, HeldByOlder: o.HeldByOlder, Unattributed: o.Unattributed,
		Since: time.Unix(o.SinceUnix, 0).UTC(), CheckedAt: time.Unix(o.CheckedAtUnix, 0).UTC(),
	}, e.Sequence)
}

func addListenerSessionsPrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	const opaque = events.PrivacyFieldOpaqueExact
	policies[privacyEventPolicyKey{EventListenerSessionsObserved, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/identity_id", opaque), privacyRule("/target_id", opaque),
		privacyRule("/target", opaque), privacyRule("/fingerprint", opaque), privacyRule("/port", opaque),
		privacyRule("/established", opaque), privacyRule("/held_by_older", opaque), privacyRule("/unattributed", opaque),
		privacyRule("/since_unix", opaque), privacyRule("/checked_at_unix", opaque))
}

func addListenerSessionsPrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventListenerSessionsObserved, 1}] = privacyPayloadShape[ListenerSessionsObserved]()
}
