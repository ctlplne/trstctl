// SPDX-License-Identifier: BUSL-1.1

package sourcecatalog

import "testing"

func FuzzValidateControlFieldCase(f *testing.F) {
	f.Add([]byte(`{"providers":[{"token_ref":"env:APPROVED"}]}`))
	f.Add([]byte(`{"providers":[{"Token_Ref":"env:SECRET"}]}`))
	f.Add([]byte(`{"providers":[{"token_ref":"env:A","token_ref":"env:B"}]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = ValidateControlFieldCase(raw)
	})
}
