// SPDX-License-Identifier: BUSL-1.1

package adcsmodern_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/adcsmodern"
	"trstctl.com/trstctl/internal/discovery/adcs"
)

// TestOptionsTightenButNeverWeakenA160L2: the operator's options only tighten
// the baseline (90 days, ECDSA or RSA, RSA of 2048 bits). Each weaker or
// inapplicable choice is refused naming its bound; a tighter one is
// canonicalized and lands in the profile with the changes that name it.
func TestOptionsTightenButNeverWeakenA160L2(t *testing.T) {
	day := 24 * time.Hour
	for name, c := range map[string]struct {
		opts adcsmodern.Options
		want string
	}{
		"longer than the baseline": {adcsmodern.Options{MaxValidity: 91 * day}, "at most 90 days"},
		"shorter than a day":       {adcsmodern.Options{MaxValidity: time.Hour}, "at least 1 day"},
		"negative":                 {adcsmodern.Options{MaxValidity: -day}, "positive"},
		"another algorithm":        {adcsmodern.Options{KeyAlgorithms: []string{"ECDSA", "Ed448"}}, `"ED448" is not one of ECDSA, RSA`},
		"a lower RSA floor":        {adcsmodern.Options{MinRSABits: 1024}, "at least 2048 bits"},
		"a floor beyond its bound": {adcsmodern.Options{MinRSABits: 32768}, "at most 16384 bits"},
		"an RSA floor without RSA": {adcsmodern.Options{KeyAlgorithms: []string{"ECDSA"}, MinRSABits: 4096}, "only when RSA keys are allowed"},
	} {
		if _, err := c.opts.Normalized(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error naming %q", name, err, c.want)
		}
	}
	normalized, err := adcsmodern.Options{MaxValidity: 30 * day, KeyAlgorithms: []string{" rsa", "RSA"}, MinRSABits: 3072}.Normalized()
	if err != nil || !slices.Equal(normalized.KeyAlgorithms, []string{"RSA"}) {
		t.Fatalf("normalized = %+v, %v", normalized, err)
	}
	if zero, err := (adcsmodern.Options{}).Normalized(); err != nil || zero.MaxValidity != 0 || zero.KeyAlgorithms != nil || zero.MinRSABits != 0 {
		t.Fatalf("the zero options = %+v, %v; want the baseline", zero, err)
	}

	tmpl := adcs.Template{Name: "WebServer", EKUs: []string{"1.3.6.1.5.5.7.3.1"}}
	m, err := adcsmodern.ModernizeWith(tmpl, "corp.example", adcsmodern.Options{MaxValidity: 30 * day, KeyAlgorithms: []string{"ecdsa"}})
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(m.Profile.MaxValidity) != 30*day || !slices.Equal(m.Profile.AllowedKeyAlgorithms, []string{"ECDSA"}) || m.Profile.MinRSABits != 0 {
		t.Fatalf("tightened profile = %+v", m.Profile)
	}
	codes := map[string]string{}
	for _, c := range m.Changes {
		codes[c.Code] = c.Detail
	}
	if codes["validity_shortened"] != "Certificates are valid for at most 30 days and renew by protocol." || codes["key_algorithms_narrowed"] != "Keys must be ECDSA." {
		t.Fatalf("changes = %v", codes)
	}
	if _, ok := codes["rsa_floor_raised"]; ok {
		t.Fatal("no RSA floor was raised, yet a change says so")
	}
	base, err := adcsmodern.Modernize(tmpl, "corp.example")
	if err != nil || time.Duration(base.Profile.MaxValidity) != adcsmodern.DefaultMaxValidity || !slices.Equal(base.Profile.AllowedKeyAlgorithms, []string{"ECDSA", "RSA"}) {
		t.Fatalf("the baseline moved: %+v %v", base.Profile, err)
	}
}
