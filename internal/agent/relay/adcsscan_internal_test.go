// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"bytes"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"trstctl.com/trstctl/internal/discovery/adcs"
)

func TestADCSSearchUsesDACLOnlySecurityDescriptorControlAUD35(t *testing.T) {
	controls := ldapSearchControls(adcs.SearchRequest{DACLOnly: true})
	if len(controls) != 1 {
		t.Fatalf("controls = %d, want one DACL-only control", len(controls))
	}
	control, ok := controls[0].(*ldap.ControlString)
	if !ok {
		t.Fatalf("control type = %T, want *ldap.ControlString", controls[0])
	}
	if control.ControlType != ldapServerSDFlagsOID || !control.Criticality {
		t.Fatalf("control = %+v, want critical %s", control, ldapServerSDFlagsOID)
	}
	want := []byte{0x30, 0x03, 0x02, 0x01, 0x04}
	if !bytes.Equal([]byte(control.ControlValue), want) {
		t.Fatalf("SDFlags control value = %x, want DACL_SECURITY_INFORMATION BER %x", []byte(control.ControlValue), want)
	}
	if got := ldapSearchControls(adcs.SearchRequest{}); len(got) != 0 {
		t.Fatalf("ordinary LDAP search got %d controls, want none", len(got))
	}
}
