// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
)

var tenantLifecycleIdentityNamespace = uuid.MustParse("735f77e0-d30f-5e76-9341-c2f9fe53ae55")

// TenantOffboardEventID gives one live registration exactly one offboard event
// identity. A retry after append-but-before-SQL-commit recovers that event.
func TenantOffboardEventID(tenantID, registrationIdentity string) string {
	return "tenant-offboard-" + uuid.NewSHA1(
		tenantLifecycleIdentityNamespace,
		[]byte("offboarded\x00"+tenantID+"\x00"+registrationIdentity),
	).String()
}

// LegacyTenantRegistrationIdentity supplies a stable offboard anchor when a
// database was seeded before retained registration events carried usable
// producer identities. It is not an event ID and cannot collide with one.
func LegacyTenantRegistrationIdentity(
	tenantID, name string,
	eventSequence uint64,
	createdAt time.Time,
) string {
	return "legacy-tenant-registration-" + uuid.NewSHA1(
		tenantLifecycleIdentityNamespace,
		[]byte("legacy\x00"+tenantID+"\x00"+name+"\x00"+
			strconv.FormatUint(eventSequence, 10)+"\x00"+createdAt.UTC().Format(time.RFC3339Nano)),
	).String()
}

// ValidateTenantLifecycleCanonical proves that a deterministic producer ID
// resolves to the exact immutable command envelope the caller reconstructed.
// Sequence is broker-assigned and expected.Time is supplied from the canonical
// event during crash recovery; both must be non-zero.
func ValidateTenantLifecycleCanonical(expected, canonical events.Event) error {
	if canonical.ID == "" || canonical.Sequence == 0 || canonical.Time.IsZero() {
		return errors.New("projections: canonical tenant lifecycle event has an incomplete envelope")
	}
	if expected.ID != canonical.ID || expected.Type != canonical.Type ||
		expected.TenantID != canonical.TenantID ||
		!expected.Time.Equal(canonical.Time) ||
		schemaVersionOf(expected) != schemaVersionOf(canonical) ||
		!bytes.Equal(expected.Data, canonical.Data) ||
		!reflect.DeepEqual(expected.Actor, canonical.Actor) {
		return fmt.Errorf("projections: deterministic tenant lifecycle event %q has a conflicting retained envelope", expected.ID)
	}
	return ValidateSchemaVersion(canonical)
}
