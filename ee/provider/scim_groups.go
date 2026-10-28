// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/ee/enterpriseauth/scim"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// A221: an IdP that pushes group membership revokes a Provider role by
// removing the operator from that role's group. A PATCH's operations apply in
// order (RFC 7644 §3.5.2): add and replace name members, remove takes them
// out, including the Entra shape (path "members" with a value array) and the
// Okta shape (members[value eq "…"]), and a remove of "members" with neither
// filter nor value empties the group. A PUT (Okta's custom-app integrations)
// names the whole membership. Members the push leaves out lose the role:
// identity and active state stay, the role becomes none (which authorizes
// nothing) and each loss is one provider.operator.role_revoked authority event
// naming the group and the SCIM token. Members it names gain the role, as an
// add always did. Standing customer delegations are kept; without a role they
// authorize nothing, and a leaver event still revokes them.

// errProviderGroupMember is a member reference to add that resolves to no
// operator identity.
var errProviderGroupMember = errors.New("group member not found")

// patchOrPutGroup applies a membership change to the role's group and answers
// with the group as trstctl then holds it.
func (h *providerSCIMHandler) patchOrPutGroup(w http.ResponseWriter, r *http.Request, token SCIMToken, role OperatorRole) {
	if h.access == nil || h.mutations == nil {
		writeProviderSCIMError(w, http.StatusInternalServerError, "", "provider SCIM mutation spine is not configured")
		return
	}
	raw, ok := readProviderSCIMBody(w, r)
	if !ok {
		return
	}
	defer secret.Wipe(raw)
	var patch []scim.PatchOperation
	var replace []string
	if r.Method == http.MethodPut {
		var group scim.Group
		if json.Unmarshal(raw, &group) != nil {
			writeProviderSCIMError(w, http.StatusBadRequest, "invalidSyntax", "malformed SCIM group")
			return
		}
		replace = make([]string, 0, len(group.Members))
		for _, member := range group.Members {
			if value := strings.TrimSpace(member.Value); value != "" {
				replace = append(replace, value)
			}
		}
	} else {
		var op scim.PatchOp
		if json.Unmarshal(raw, &op) != nil {
			writeProviderSCIMError(w, http.StatusBadRequest, "invalidSyntax", "malformed SCIM group patch")
			return
		}
		patch = op.Operations
	}
	current, err := h.groupMembers(r.Context(), role)
	if err != nil {
		writeProviderSCIMError(w, http.StatusInternalServerError, "", "get group failed")
		return
	}
	resolver := providerGroupResolver{ctx: r.Context(), access: h.access, seen: map[string]OperatorIdentity{}}
	var desired map[string]OperatorIdentity
	if r.Method == http.MethodPut {
		desired, err = resolver.replaceWith(replace)
	} else {
		desired, err = resolver.fold(current, patch)
	}
	if errors.Is(err, errProviderGroupMember) {
		writeProviderSCIMError(w, http.StatusNotFound, "", "group member not found")
		return
	}
	if err != nil {
		writeProviderSCIMError(w, http.StatusInternalServerError, "", "resolve group members failed")
		return
	}
	baseKey, binding := providerSCIMMutationKey(r, token, raw), providerSCIMBinding(r, token, raw)
	group := "provider-" + string(role)
	for _, id := range sortedIdentityIDs(desired) {
		if _, member := current[id]; member {
			continue
		}
		identity := desired[id]
		identity.Role, identity.Active, identity.UpdatedAt = role, true, h.clock().UTC()
		identity.DeprovisionedAt = time.Time{}
		if _, emitErr := h.emitIdentityReason(r.Context(), token, EventOperatorUpserted, identity, baseKey+":"+identity.ID, binding,
			"added to SCIM group "+group); emitErr != nil {
			h.writeMutationError(w, emitErr)
			return
		}
	}
	for _, id := range sortedIdentityIDs(current) {
		if _, kept := desired[id]; kept {
			continue
		}
		identity := current[id]
		identity.Role, identity.UpdatedAt = "", h.clock().UTC()
		if _, emitErr := h.emitIdentityReason(r.Context(), token, EventOperatorRoleRevoked, identity, baseKey+":revoke:"+identity.ID, binding,
			"removed from SCIM group "+group+"; the "+string(role)+" role is revoked"); emitErr != nil {
			h.writeMutationError(w, emitErr)
			return
		}
	}
	answer, err := h.scimGroup(r.Context(), role, providerSCIMBase(r))
	if err != nil {
		writeProviderSCIMError(w, http.StatusInternalServerError, "", "get group failed")
		return
	}
	writeProviderSCIM(w, http.StatusOK, answer)
}

// groupMembers is the role's group as trstctl holds it: the active operators
// holding the role, by id.
func (h *providerSCIMHandler) groupMembers(ctx context.Context, role OperatorRole) (map[string]OperatorIdentity, error) {
	rows, err := h.access.ListOperatorAccess(ctx)
	if err != nil {
		return nil, err
	}
	members := map[string]OperatorIdentity{}
	for _, row := range rows {
		if row.Identity.Active && row.Identity.Role == role {
			members[row.Identity.ID] = row.Identity
		}
	}
	return members, nil
}

// providerGroupResolver turns the member references an IdP sends (the SCIM
// id trstctl returned, or an external id or user name) into identities.
type providerGroupResolver struct {
	ctx    context.Context
	access OperatorAccessStore
	seen   map[string]OperatorIdentity
}

func (g providerGroupResolver) resolve(ref string) (OperatorIdentity, bool, error) {
	ref = strings.TrimSpace(ref)
	if identity, ok := g.seen[ref]; ok {
		return identity, true, nil
	}
	identity, err := g.access.ResolveOperator(g.ctx, ref)
	if errors.Is(err, ErrNotFound) {
		return OperatorIdentity{}, false, nil
	}
	if err != nil {
		return OperatorIdentity{}, false, err
	}
	g.seen[ref] = identity
	return identity, true, nil
}

// named resolves members to add; one that resolves to no operator refuses the
// whole change before anything is recorded.
func (g providerGroupResolver) named(refs []string, into map[string]OperatorIdentity) error {
	for _, ref := range refs {
		identity, found, err := g.resolve(ref)
		if err != nil {
			return err
		}
		if !found {
			return errProviderGroupMember
		}
		into[identity.ID] = identity
	}
	return nil
}

func (g providerGroupResolver) replaceWith(refs []string) (map[string]OperatorIdentity, error) {
	desired := map[string]OperatorIdentity{}
	return desired, g.named(refs, desired)
}

// fold applies the operations in order. A member to remove that resolves to
// no operator, or is not in the group, changes nothing: the IdP's view was
// stale, and a retried remove must succeed.
func (g providerGroupResolver) fold(current map[string]OperatorIdentity, ops []scim.PatchOperation) (map[string]OperatorIdentity, error) {
	desired := maps.Clone(current)
	for _, op := range ops {
		if removesEveryMember(op) {
			desired = map[string]OperatorIdentity{}
			continue
		}
		parsed := scim.ParseGroupPatch([]scim.PatchOperation{op})
		if parsed.ReplaceAll != nil {
			desired = map[string]OperatorIdentity{}
			if err := g.named(*parsed.ReplaceAll, desired); err != nil {
				return nil, err
			}
		}
		if err := g.named(parsed.Add, desired); err != nil {
			return nil, err
		}
		for _, ref := range parsed.Remove {
			identity, found, err := g.resolve(ref)
			if err != nil {
				return nil, err
			}
			if found {
				delete(desired, identity.ID)
			}
		}
	}
	return desired, nil
}

// removesEveryMember is RFC 7644 §3.5.2.2's remove of a multi-valued
// attribute without a filter: every member goes. Entra's remove carries a
// value array naming the members, and is not this.
func removesEveryMember(op scim.PatchOperation) bool {
	value := bytes.TrimSpace(op.Value)
	return strings.EqualFold(strings.TrimSpace(op.Op), "remove") && strings.EqualFold(strings.TrimSpace(op.Path), "members") &&
		(len(value) == 0 || bytes.Equal(value, []byte("null")))
}

func sortedIdentityIDs(members map[string]OperatorIdentity) []string {
	ids := make([]string, 0, len(members))
	for id := range members {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
