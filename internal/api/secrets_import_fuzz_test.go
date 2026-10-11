// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"net/http/httptest"
	"testing"
)

// FuzzDecodeSecretImportRequest exercises the custom duplicate-field parser at
// the untrusted HTTP boundary. A rejected body must not retain any partially
// decoded secret values; a valid body must pass the same name checks as execute.
func FuzzDecodeSecretImportRequest(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"prefix":"qa","values":{"a":"one","b":"two"}}`),
		[]byte(`{"values":{"a":"first","a":"second"}}`),
		[]byte(`{"values":{"a":"first"},"values":{"b":"second"}}`),
		[]byte(`{"values":{"a":"first"}} {}`),
		[]byte(`{"values":{"../bad":"value"}}`),
		[]byte(`{"values":{"a":"one","b":23}}`),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		request := httptest.NewRequest("POST", "/api/v1/secrets/store/import", bytes.NewReader(raw))
		decoded, err := decodeSecretImportRequest(request)
		defer wipeSecretImportRequest(&decoded)
		if err != nil {
			if len(decoded.Values) != 0 {
				t.Fatalf("rejected body retained %d decoded secret values", len(decoded.Values))
			}
			return
		}
		_, _ = applicationSecretImportNames(decoded)
	})
}
