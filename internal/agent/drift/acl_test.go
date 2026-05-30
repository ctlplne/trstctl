package drift

import "testing"

// sddlAllowsBroad is the platform-independent decision behind Windows ACL drift
// detection, so it is tested everywhere (not only on Windows). It must flag an
// allow ACE for a broad principal and ignore admin-only DACLs, deny ACEs,
// empty-rights ACEs, and the SACL.
func TestSDDLAllowsBroad(t *testing.T) {
	cases := []struct {
		name string
		sddl string
		want string // expected broad principal name, "" for none
	}{
		{
			name: "admin only is fine",
			sddl: "O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-21-1-2-3-1001)",
			want: "",
		},
		{
			name: "everyone alias is loosening",
			sddl: "O:BAG:BAD:(A;;FA;;;SY)(A;;FR;;;WD)",
			want: "Everyone",
		},
		{
			name: "everyone numeric SID is loosening",
			sddl: "D:(A;;FR;;;S-1-1-0)",
			want: "Everyone",
		},
		{
			name: "authenticated users is loosening",
			sddl: "D:(A;;FRFX;;;AU)",
			want: "Authenticated Users",
		},
		{
			name: "builtin users is loosening",
			sddl: "D:PAI(A;;FR;;;BU)(A;;FA;;;SY)",
			want: "Users",
		},
		{
			name: "deny everyone is not loosening",
			sddl: "D:(D;;FA;;;WD)(A;;FA;;;SY)",
			want: "",
		},
		{
			name: "empty rights is not access",
			sddl: "D:(A;;;;;WD)",
			want: "",
		},
		{
			name: "broad principal only in SACL is ignored",
			sddl: "O:BAG:BAD:(A;;FA;;;SY)S:(AU;SAFA;FA;;;WD)",
			want: "",
		},
		{
			name: "no dacl",
			sddl: "O:BAG:BA",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name, broad := sddlAllowsBroad(tc.sddl)
			if (tc.want != "") != broad || name != tc.want {
				t.Errorf("sddlAllowsBroad(%q) = (%q, %v), want (%q, %v)", tc.sddl, name, broad, tc.want, tc.want != "")
			}
		})
	}
}
