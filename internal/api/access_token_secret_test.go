package api

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestAPITokenCreateResponseTokenUsesSecretJSONBytes(t *testing.T) {
	field, ok := reflect.TypeOf(apiTokenCreateResponse{}).FieldByName("Token")
	if !ok {
		t.Fatal("apiTokenCreateResponse.Token field is missing")
	}
	if field.Type.Kind() == reflect.String {
		t.Fatalf("apiTokenCreateResponse.Token is %s; raw bearer token material must be byte-backed", field.Type)
	}
	if want := reflect.TypeOf(secretJSONBytes{}); field.Type != want {
		t.Fatalf("apiTokenCreateResponse.Token type = %s, want %s", field.Type, want)
	}

	resp := &apiTokenCreateResponse{Token: secretJSONBytes([]byte("trst_secret_token"))}
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`"token":"trst_secret_token"`)) {
		t.Fatalf("token did not encode as JSON string: %s", body)
	}

	resp.wipeSecrets()
	if bytes.Contains([]byte(resp.Token), []byte("trst_secret_token")) {
		t.Fatalf("wipeSecrets left token bytes in response: %q", []byte(resp.Token))
	}
}
