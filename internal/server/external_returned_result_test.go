// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/config"
)

type returnedResultTestCA struct {
	name      string
	ambiguous bool
	calls     atomic.Int32
	minted    chan ca.Certificate
}

func (c *returnedResultTestCA) Name() string { return c.name }
func (c *returnedResultTestCA) Issue(_ context.Context, req ca.IssueRequest) (ca.Certificate, error) {
	c.calls.Add(1)
	if req.ProviderIdempotencyKey == "" {
		return ca.Certificate{}, errors.New("provider token missing")
	}
	cert, err := testExternalCACertificate(req, c.name)
	if err != nil {
		return ca.Certificate{}, err
	}
	select {
	case c.minted <- cert:
	default:
	}
	if c.ambiguous {
		return ca.Certificate{}, errors.New("owned provider returned no certificate after mint")
	}
	return cert, nil
}

// Once the provider has returned its exact public result, a later local database
// failure must be recoverable without another provider call. This is distinct
// from an ambiguous upstream failure, where no usable result reached this process.
func TestExternalCAReturnedResultSurvivesRecordingFailure(t *testing.T) {
	const caID = "returned-result"
	const key = "returned-before-record-failure"
	upstream := &returnedResultTestCA{name: caID, minted: make(chan ca.Certificate, 1)}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.APIOptions = append(d.APIOptions, api.WithInsecureHeaderResolver())
		d.ExternalCAs = []ExternalCA{{ID: caID, Type: "non-replayable-test", CA: upstream}}
	})
	// The real tenant-scoped recording reaches PostgreSQL and rolls back after
	// its immutable event append. This only affects the owned test authority.
	_, err := h.store.SystemPool().Exec(t.Context(), `CREATE FUNCTION qa_returned_result_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id='11111111-1111-1111-1111-111111111111'::uuid AND NEW.source='external-ca:returned-result' THEN RAISE EXCEPTION 'owned returned-result recording failure'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER qa_returned_result_fail BEFORE INSERT OR UPDATE ON certificates FOR EACH ROW EXECUTE FUNCTION qa_returned_result_fail()`)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := h.store.SystemPool().Exec(ctx, `DROP TRIGGER qa_returned_result_fail ON certificates; DROP FUNCTION qa_returned_result_fail()`); err != nil {
				t.Error(err)
			}
		})
	}
	t.Cleanup(release)
	startServedExternalCADispatcher(t, h)
	body := externalCAIssueRequestBody(t, "returned-result.served.test")
	code, raw := doExternalCARequest(t, h, http.MethodPost, "/api/v1/external-cas/"+caID+"/issue", key, body)
	if code != http.StatusBadGateway {
		t.Fatalf("recording failure returned %d, want502 and no prematurely usable result: %s", code, raw)
	}
	var issued ca.Certificate
	select {
	case issued = <-upstream.minted:
	default:
		t.Fatal("provider never returned the original real certificate")
	}
	if upstream.calls.Load() != 1 {
		t.Fatalf("provider calls=%d", upstream.calls.Load())
	}
	intentID := externalCAIntentOutboxID(t, h, key+":external-ca:"+caID)
	failed, err := h.srv.outbox.Get(t.Context(), h.tenant, intentID)
	if err != nil || failed.LastError != "external_ca_record_failed" {
		t.Fatalf("recording fault not observed at required stage: %+v err=%v", failed, err)
	}
	if _, err := h.store.GetIssuedCertificateRecovery(t.Context(), h.tenant, key+":external-ca:"+caID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("fault did not roll back inventory: %v", err)
	}
	release()
	forceExternalCAOutboxDue(t, h, key+":external-ca:"+caID)
	code, raw = doExternalCARequest(t, h, http.MethodPost, "/api/v1/external-cas/"+caID+"/issue", key, body)
	if code != http.StatusCreated {
		t.Fatalf("exact returned result was lost after local recording failure: retry=%d body=%s", code, raw)
	}
	var recovered externalCAIssueResponse
	if err := json.Unmarshal(raw, &recovered); err != nil {
		t.Fatal(err)
	}
	if recovered.Serial != issued.Serial || recovered.CertificatePEM != string(issued.CertificatePEM) {
		t.Fatal("recovery changed the original provider result")
	}
	waitForOutboxStatus(t, h.srv.outbox, h.tenant, intentID, "delivered")
	if upstream.calls.Load() != 1 {
		t.Fatalf("recovery re-entered non-replayable provider: calls=%d", upstream.calls.Load())
	}
	code, again := doExternalCARequest(t, h, http.MethodPost, "/api/v1/external-cas/"+caID+"/issue", key, body)
	if code != http.StatusCreated || !bytes.Equal(raw, again) || upstream.calls.Load() != 1 {
		t.Fatal("completed replay changed result or called provider")
	}
}

func TestExternalCAAmbiguousProviderFailureStillRefusesReplay(t *testing.T) {
	const caID = "ambiguous-return"
	const key = "ambiguous-provider-result"
	upstream := &returnedResultTestCA{name: caID, ambiguous: true, minted: make(chan ca.Certificate, 1)}
	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.APIOptions = append(d.APIOptions, api.WithInsecureHeaderResolver())
		d.ExternalCAs = []ExternalCA{{ID: caID, Type: "non-replayable-test", CA: upstream}}
	})
	startServedExternalCADispatcher(t, h)
	body := externalCAIssueRequestBody(t, "ambiguous-return.served.test")
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			forceExternalCAOutboxDue(t, h, key+":external-ca:"+caID)
		}
		code, raw := doExternalCARequest(t, h, http.MethodPost, "/api/v1/external-cas/"+caID+"/issue", key, body)
		if code != http.StatusBadGateway {
			t.Fatalf("ambiguous provider result unexpectedly usable: %d %s", code, raw)
		}
	}
	if upstream.calls.Load() != 1 {
		t.Fatalf("ambiguous provider was called again: %d", upstream.calls.Load())
	}
	if _, err := h.store.GetIssuedCertificateRecovery(t.Context(), h.tenant, key+":external-ca:"+caID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("invented certificate recovery: %v", err)
	}
}
