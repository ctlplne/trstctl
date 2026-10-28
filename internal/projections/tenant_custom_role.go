// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// A207: a tenant defines custom roles as named subsets of the core permission
// vocabulary and deletes ones nobody holds.
const (
	EventTenantCustomRoleUpserted  = "access.role.upserted"
	EventTenantCustomRoleDeleted   = "access.role.deleted"
	tenantCustomRoleDescriptionMax = 512
)

// TenantCustomRoleUpserted defines or redefines a custom role.
type TenantCustomRoleUpserted struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions"`
}

// TenantCustomRoleDeleted deletes a custom role.
type TenantCustomRoleDeleted struct {
	Name string `json:"name"`
}

var tenantCustomRoleName = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)

// ValidateTenantCustomRoleName refuses a malformed name and a built-in one.
func ValidateTenantCustomRoleName(name string) error {
	if !tenantCustomRoleName.MatchString(name) {
		return errors.New("a custom role name is 2 to 63 lowercase letters, digits or hyphens, starting with a letter")
	}
	if _, builtin := authz.BuiltinRoles()[name]; builtin {
		return fmt.Errorf("%s is a built-in role", name)
	}
	return nil
}

// ValidateTenantCustomRole checks a definition: a free name, a description of
// at most 512 characters, and one or more distinct permissions from the custom
// role vocabulary.
func ValidateTenantCustomRole(pl TenantCustomRoleUpserted) error {
	if err := ValidateTenantCustomRoleName(pl.Name); err != nil {
		return err
	}
	if len(pl.Description) > tenantCustomRoleDescriptionMax {
		return fmt.Errorf("a custom role description is at most %d characters", tenantCustomRoleDescriptionMax)
	}
	if len(pl.Permissions) == 0 {
		return errors.New("a custom role grants at least one permission")
	}
	allowed := map[authz.Permission]bool{}
	for _, p := range authz.CustomRoleVocabulary() {
		allowed[p] = true
	}
	seen := map[string]bool{}
	for _, p := range pl.Permissions {
		if !allowed[authz.Permission(p)] {
			return fmt.Errorf("%q is not a permission a custom role can grant", p)
		}
		if seen[p] {
			return fmt.Errorf("permission %q is listed twice", p)
		}
		seen[p] = true
	}
	return nil
}

func (p *Projector) applyTenantCustomRoleTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventTenantCustomRoleUpserted:
		var pl TenantCustomRoleUpserted
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if err := ValidateTenantCustomRole(pl); err != nil {
			return true, fmt.Errorf("projections: %s: %w", e.Type, err)
		}
		return true, p.store.ApplyTenantCustomRoleUpsertedTx(ctx, tx, store.TenantCustomRole{
			TenantID: e.TenantID, Name: pl.Name, Description: pl.Description, Permissions: pl.Permissions,
			UpdatedAt: e.Time, EventSequence: e.Sequence,
		})
	case EventTenantCustomRoleDeleted:
		var pl TenantCustomRoleDeleted
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if err := ValidateTenantCustomRoleName(pl.Name); err != nil {
			return true, fmt.Errorf("projections: %s: %w", e.Type, err)
		}
		return true, p.store.ApplyTenantCustomRoleDeletedTx(ctx, tx, e.TenantID, pl.Name, e.Time, e.Sequence)
	}
	return false, nil
}
