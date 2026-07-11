// SPDX-License-Identifier: MPL-2.0

package secret

import (
	"encoding/json"
	"encoding/xml"
	"testing"
)

func TestJSONBytesRoundTripEscapesWithoutStringField(t *testing.T) {
	want := []byte("p@ss\nword/雪😀")
	raw, err := json.Marshal(struct {
		Value JSONBytes `json:"value"`
	}{Value: JSONBytes(want)})
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Value JSONBytes `json:"value"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if string(decoded.Value) != string(want) {
		t.Fatalf("decoded bytes differ: %q", decoded.Value)
	}
	Wipe(decoded.Value)
}

func TestJSONBytesUnmarshalXML(t *testing.T) {
	var decoded struct {
		Value JSONBytes `xml:"Secret"`
	}
	if err := xml.Unmarshal([]byte(`<Response><Secret>byte-native-value</Secret></Response>`), &decoded); err != nil {
		t.Fatal(err)
	}
	if string(decoded.Value) != "byte-native-value" {
		t.Fatalf("XML value = %q", decoded.Value)
	}
	Wipe(decoded.Value)
}

func TestJSONBytesRejectsMalformedSurrogates(t *testing.T) {
	var value JSONBytes
	if err := json.Unmarshal([]byte(`"\ud800"`), &value); err == nil {
		t.Fatal("accepted lone high surrogate")
	}
}
