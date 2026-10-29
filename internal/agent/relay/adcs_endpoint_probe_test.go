// SPDX-License-Identifier: BUSL-1.1
package relay

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/discovery/adcs"
)

type forbiddenProbeBody struct{ reads *atomic.Int32 }

func (b forbiddenProbeBody) Read([]byte) (int, error) { b.reads.Add(1); return 0, io.EOF }
func (forbiddenProbeBody) Close() error               { return nil }

func TestADCSLDAPEndpointProbeExecutesFixedPageWithoutCredentialsOrBodies(t *testing.T) {
	intent := adcs.InventoryIntent{EndpointProbe: &adcs.EndpointProbeOptions{Enabled: true, DNSSuffixes: []string{"corp.example"}}}
	inventory := adcs.Inventory{}
	for index := range 8 {
		inventory.EnrollmentServices = append(inventory.EnrollmentServices, adcs.EnrollmentService{Name: fmt.Sprintf("CA%02d", index), DNSName: fmt.Sprintf("ca%02d.corp.example", index)})
	}
	var calls, reads, active, maxActive, unsafe atomic.Int32
	client := adcsDoerFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		current := active.Add(1)
		defer active.Add(-1)
		for {
			prior := maxActive.Load()
			if current <= prior || maxActive.CompareAndSwap(prior, current) {
				break
			}
		}
		if req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" || req.URL.User != nil || req.Method != "GET" || strings.Contains(req.URL.Path, "mscep_admin") {
			unsafe.Add(1)
		}
		if deadline, ok := req.Context().Deadline(); !ok || time.Until(deadline) > 6*time.Second {
			unsafe.Add(1)
		}
		return &http.Response{StatusCode: 401, Header: http.Header{"Www-Authenticate": []string{"Negotiate secret-challenge", "NTLM TlRMTVN-private"}, "Set-Cookie": []string{"private-cookie"}}, Body: forbiddenProbeBody{&reads}}, nil
	})
	restrictions := func(context.Context, adcs.EnrollmentService) adcs.EnrollmentAgentRestrictions {
		return adcs.EnrollmentAgentRestrictions{State: adcs.EvidenceUnobserved, Source: "standin"}
	}
	if err := enrichADCSInventory(t.Context(), intent, &inventory, client, restrictions); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 24 || reads.Load() != 0 || unsafe.Load() != 0 || maxActive.Load() > 4 {
		t.Fatalf("probe bounds calls=%d reads=%d unsafe=%d max=%d", calls.Load(), reads.Load(), unsafe.Load(), maxActive.Load())
	}
	if inventory.EndpointProbePage == nil || inventory.EndpointProbePage.TotalTargets != 32 || inventory.EndpointProbePage.NextOffset != 24 || inventory.EndpointProbePage.Complete {
		t.Fatalf("page=%+v", inventory.EndpointProbePage)
	}
	for _, service := range inventory.EnrollmentServices {
		if service.EndpointProbe == nil {
			t.Fatal("service omitted coverage")
		}
		for _, e := range service.Endpoints {
			if e.Source != "ldap_dns" || e.HTTPStatus != 401 || strings.Join(e.Authentication, ",") != "NTLM,Negotiate" {
				t.Fatalf("endpoint=%+v", e)
			}
		}
	}
}

func TestADCSLDAPEndpointProbeCancellationIsUnassessedAndDefaultOffDoesNoIO(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		intent := adcs.InventoryIntent{}
		if enabled {
			intent.EndpointProbe = &adcs.EndpointProbeOptions{Enabled: true, DNSSuffixes: []string{"corp.example"}}
		}
		inventory := adcs.Inventory{EnrollmentServices: []adcs.EnrollmentService{{Name: "CA", DNSName: "ca.corp.example"}}}
		var calls atomic.Int32
		client := adcsDoerFunc(func(*http.Request) (*http.Response, error) { calls.Add(1); return nil, context.Canceled })
		if err := enrichADCSInventory(ctx, intent, &inventory, client, func(context.Context, adcs.EnrollmentService) adcs.EnrollmentAgentRestrictions {
			return adcs.EnrollmentAgentRestrictions{State: adcs.EvidenceUnobserved, Source: "standin"}
		}); err != nil {
			t.Fatal(err)
		}
		if calls.Load() != 0 {
			t.Fatal("cancelled or default-off probe performed HTTP")
		}
		if enabled {
			if len(inventory.EnrollmentServices[0].Endpoints) != 4 {
				t.Fatal("cancelled targets disappeared")
			}
			for _, e := range inventory.EnrollmentServices[0].Endpoints {
				if e.State != adcs.EndpointNotChecked || e.NotCheckedReason != "deadline_or_cancellation" || e.HTTPStatus != 0 {
					t.Fatalf("unattempted target=%+v", e)
				}
			}
		}
	}
}

func TestADCSLDAPEndpointProbePageIsNotStarvedByCAPolicyReads(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	intent := adcs.InventoryIntent{EndpointProbe: &adcs.EndpointProbeOptions{Enabled: true, DNSSuffixes: []string{"corp.example"}}}
	inventory := adcs.Inventory{EnrollmentServices: []adcs.EnrollmentService{{Name: "CA", DNSName: "ca.corp.example"}}}
	var calls atomic.Int32
	client := adcsDoerFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: 401, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	if err := enrichADCSInventory(ctx, intent, &inventory, client, func(context.Context, adcs.EnrollmentService) adcs.EnrollmentAgentRestrictions {
		cancel()
		return adcs.EnrollmentAgentRestrictions{State: adcs.EvidenceUnobserved, Source: "policy_read_deadline"}
	}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 4 {
		t.Fatalf("CA policy read starved opted-in endpoint page: attempts=%d", calls.Load())
	}
}
