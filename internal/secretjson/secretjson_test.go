// SPDX-License-Identifier: MPL-2.0

package secretjson_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/secretjson"
)

func TestStringBytesMarshalsAsJSONString(t *testing.T) {
	body, err := json.Marshal(struct {
		Key secretjson.StringBytes `json:"key"`
	}{Key: secretjson.StringBytes([]byte("line1\n\"line2\""))})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(body), `{"key":"line1\n\"line2\""}`; got != want {
		t.Fatalf("json = %s, want %s", got, want)
	}
}

func TestBase64BytesMarshalsAsBase64JSONString(t *testing.T) {
	body, err := json.Marshal(struct {
		Key secretjson.Base64Bytes `json:"key"`
	}{Key: secretjson.Base64Bytes([]byte("secret-key"))})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(body), `{"key":"c2VjcmV0LWtleQ=="}`; got != want {
		t.Fatalf("json = %s, want %s", got, want)
	}
}

func TestBase64BytesUnmarshalsBase64JSONString(t *testing.T) {
	old := []byte("old-key-material")
	body := struct {
		Key secretjson.Base64Bytes `json:"key"`
	}{Key: secretjson.Base64Bytes(old)}
	if err := json.Unmarshal([]byte(`{"key":"c2VjcmV0LWtleQ=="}`), &body); err != nil {
		t.Fatal(err)
	}
	if got, want := string(body.Key), "secret-key"; got != want {
		t.Fatalf("key = %q, want %q", got, want)
	}
	if !bytes.Equal(old, make([]byte, len(old))) {
		t.Fatalf("replaced key buffer was not wiped: %x", old)
	}
	if err := json.Unmarshal([]byte(`{"key":"%%%"}`), &body); err == nil {
		t.Fatal("invalid base64 was accepted")
	}
}

func TestStringBytesUnmarshalsJSONString(t *testing.T) {
	var body struct {
		Token secretjson.StringBytes `json:"token"`
	}
	if err := json.Unmarshal([]byte(`{"token":"tok\u0065n\nvalue"}`), &body); err != nil {
		t.Fatal(err)
	}
	if got, want := string(body.Token), "token\nvalue"; got != want {
		t.Fatalf("token = %q, want %q", got, want)
	}
}
