// SPDX-License-Identifier: BUSL-1.1
package servicedependents

import (
	"encoding/hex"
	"errors"
	"github.com/go-ldap/ldap/v3"
	googleuuid "github.com/google/uuid"
	"strings"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/windependents"
	"unicode/utf8"
)

const Reconcile = "reconcile"

// ReconcilePrincipal freezes public native reset authority. The designated
// writer's credential and its reference never enter a dependent plan or job.
type ReconcilePrincipal struct {
	DN   string `json:"dn"`
	SID  string `json:"sid"`
	GUID string `json:"guid"`
}

func (intent RotationIntent) validateMode() error {
	if intent.Mode == "" && intent.Reconcile == nil {
		return nil
	}
	refused := errors.New("service dependents: exact distinct designated reconcile principal required")
	p := intent.Reconcile
	if intent.Mode != Reconcile || p == nil || len(p.DN) == 0 || len(p.DN) > 4096 || strings.TrimSpace(p.DN) != p.DN || !utf8.ValidString(p.DN) || !windependents.ValidAccountSID(p.SID) || !strings.HasPrefix(p.SID, "S-1-5-21-") || p.SID == intent.Plan.Account.SID || p.GUID == intent.Plan.Account.GUID {
		return refused
	}
	guid, e := hex.DecodeString(p.GUID)
	if e != nil || len(guid) != 16 || p.GUID != strings.ToLower(p.GUID) || strings.Trim(p.GUID, "0") == "" {
		return refused
	}
	writer, e := ldap.ParseDN(p.DN)
	target, err := ldap.ParseDN(intent.Plan.Account.DN)
	if e != nil || err != nil || len(writer.RDNs) == 0 || writer.EqualFold(target) {
		return refused
	}
	return nil
}

// ReconciliationReviewSourceID scopes the immutable review to the tenant and
// operation, even before a reset command or read-model row exists.
func ReconciliationReviewSourceID(tenantID, id string) string {
	return googleuuid.NewSHA1(googleuuid.NameSpaceOID, []byte("trstctl.service-dependent.reconcile-review\x00"+tenantID+"\x00"+id)).String()
}

// ReconcileCommandKey serializes the first approved command for one vault
// credential, including across provider choices, without indexing its raw name.
func ReconcileCommandKey(tenantID, secretName string) string {
	return crypto.SHA256Hex([]byte("trstctl.service-dependent.reconcile-key.v1\x00" + tenantID + "\x00" + secretName))
}
