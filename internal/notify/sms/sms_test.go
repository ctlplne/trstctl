// SPDX-License-Identifier: BUSL-1.1

package sms_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/notify/sms"
)

func TestSMSConformanceAndPayload(t *testing.T) {
	doer := &captureDoer{status: http.StatusAccepted}
	ch := sms.New("https://sms-gateway.example/alerts", "trstctl", []string{"+15550100"}, []byte("sms-token"), sms.WithHTTPClient(doer))
	if err := notify.Conform(context.Background(), ch); err != nil {
		t.Fatalf("sms channel failed conformance: %v", err)
	}
	if ch.Name() != "sms" {
		t.Fatalf("Name() = %q, want sms", ch.Name())
	}
	if doer.auth != "Bearer sms-token" {
		t.Fatalf("Authorization = %q, want bearer token", doer.auth)
	}
	var body struct {
		To       []string `json:"to"`
		Text     string   `json:"text"`
		TenantID string   `json:"tenant_id"`
	}
	if err := json.Unmarshal(doer.body, &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(body.To) != 1 || body.To[0] != "+15550100" {
		t.Fatalf("to = %#v, want configured recipient", body.To)
	}
	if body.TenantID != "t-conformance" || !strings.Contains(body.Text, "conformance.example") {
		t.Fatalf("unexpected sms body: %+v", body)
	}
}

func TestSMSNon2xxNamesChannel(t *testing.T) {
	ch := sms.New("https://sms-gateway.example/alerts", "", []string{"+15550100"}, nil, sms.WithHTTPClient(&captureDoer{status: http.StatusTooManyRequests, response: "quota exceeded"}))
	err := ch.Notify(context.Background(), notify.Alert{TenantID: "t1", Subject: "cn=api"})
	if err == nil || !strings.Contains(err.Error(), "sms: status 429") {
		t.Fatalf("Notify error = %v, want sms status", err)
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
