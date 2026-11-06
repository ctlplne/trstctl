// SPDX-License-Identifier: BUSL-1.1
package accessdesktop

import (
	"encoding/json"
	"testing"
)

func TestADDesktopRequiresExplicitReviewedAccountIdentities(t *testing.T) {
	var binding Binding
	if err := json.Unmarshal([]byte(`{"address":"directory-desktop.example:3389","certificate_sha256":"abababababababababababababababababababababababababababababababab","width":800,"height":600,"account_kind":"active_directory"}`), &binding); err != nil {
		t.Fatal(err)
	}
	if binding.Validate() == nil {
		t.Fatal("AD desktop accepted without a reviewed account identity")
	}
}
