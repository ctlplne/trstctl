// SPDX-License-Identifier: BUSL-1.1

package siem_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/notify/siem"
)

func TestSIEMConformanceAndPayload(t *testing.T) {
	doer := &captureDoer{status: http.StatusOK}
	ch := siem.New("https://siem.example/collector", []byte("siem-token"), siem.WithSource("trstctl-prod"), siem.WithHTTPClient(doer))
	if err := notify.Conform(context.Background(), ch); err != nil {
		t.Fatalf("siem channel failed conformance: %v", err)
	}
	if ch.Name() != "siem" {
		t.Fatalf("Name() = %q, want siem", ch.Name())
	}
	if doer.auth != "Bearer siem-token" {
		t.Fatalf("Authorization = %q, want bearer token", doer.auth)
	}
	var body struct {
		Source    string       `json:"source"`
		Message   string       `json:"message"`
		TenantID  string       `json:"tenant_id"`
		EventType string       `json:"event_type"`
		Alert     notify.Alert `json:"alert"`
	}
	if err := json.Unmarshal(doer.body, &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Source != "trstctl-prod" || body.TenantID != "t-conformance" || body.EventType != notify.KindCertificateExpiry {
		t.Fatalf("unexpected siem body: %+v", body)
	}
	if !strings.Contains(body.Message, "conformance.example") || body.Alert.Subject != "cn=conformance.example" {
		t.Fatalf("siem event did not carry alert context: %+v", body)
	}
}

func TestSIEMNon2xxNamesChannel(t *testing.T) {
	ch := siem.New("https://siem.example/collector", nil, siem.WithHTTPClient(&captureDoer{status: http.StatusBadGateway, response: "collector down"}))
	err := ch.Notify(context.Background(), notify.Alert{TenantID: "t1", Subject: "cn=api"})
	if err == nil || !strings.Contains(err.Error(), "siem: status 502") {
		t.Fatalf("Notify error = %v, want siem status", err)
	}
}

type captureDoer struct {
	status   int
	response string
	auth     string
	body     []byte
}

func (d *captureDoer) Do(req *http.Request) (*http.Response, error) {
	d.auth = req.Header.Get("Authorization")
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	d.body = body
	status := d.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewBufferString(d.response)),
	}, nil
}
