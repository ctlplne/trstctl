// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/usage"
)

var applicationSecretImportNamespace = googleuuid.MustParse("7bd2f615-651c-51f4-9c37-31a562b0e60d")

// Reject duplicate JSON keys before a map assignment can drop an earlier
// secret byte slice. It also prevents an operator review of one name/value
// from silently executing the last spelling of a duplicated name (AN-8).
func (r *secretImportRequest) UnmarshalJSON(raw []byte) error {
	wipeSecretImportRequest(r)
	r.Prefix = ""
	r.Values = make(map[string]secretJSONBytes)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return errors.New("secret import must be a JSON object")
	}
	seen := make(map[string]bool)
	for decoder.More() {
		field, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := field.(string)
		if !ok || seen[name] {
			return errors.New("secret import has a duplicate or invalid field")
		}
		seen[name] = true
		switch name {
		case "prefix":
			if err := decoder.Decode(&r.Prefix); err != nil {
				return err
			}
		case "values":
			if err := decodeSecretImportValues(decoder, r.Values); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown secret import field %q", name)
		}
	}
	if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
		return errors.New("secret import JSON object is incomplete")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("secret import contains trailing JSON data")
	}
	return nil
}

func decodeSecretImportValues(decoder *json.Decoder, values map[string]secretJSONBytes) error {
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return errors.New("secret import values must be a JSON object")
	}
	for decoder.More() {
		field, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := field.(string)
		if !ok {
			return errors.New("secret import value name is invalid")
		}
		if _, duplicate := values[name]; duplicate {
			return errors.New("secret import contains a duplicate secret name")
		}
		var value secretJSONBytes
		if err := decoder.Decode(&value); err != nil {
			value.wipe()
			return err
		}
		values[name] = value
	}
	if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
		return errors.New("secret import values object is incomplete")
	}
	return nil
}

type secretImportResponse struct {
	BatchID string                              `json:"batch_id"`
	Count   int                                 `json:"count"`
	Items   []store.ApplicationSecretImportItem `json:"items"`
}

func (a *API) importSecretsEventSourced(w http.ResponseWriter, r *http.Request, idempotencyKey string) {
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	req, err := decodeSecretImportRequest(r)
	if err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	defer wipeSecretImportRequest(&req)
	names, err := applicationSecretImportNames(req)
	if err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	keyDigest, binding, err := a.applicationSecretRequestBinding(
		tenantID, idempotencyKey, principal, r.Method, r.URL.EscapedPath(),
		"import", "native", "", req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateBound(w, r, idempotencyKey, binding, func(ctx context.Context, authorizedTenant string) (int, any, error) {
		if authorizedTenant != tenantID {
			return 0, nil, errors.New("api: application-secret import tenant changed")
		}
		return withStoredSecretCreationFence(ctx, tenantID, func(work context.Context) (int, any, error) {
			return a.executeApplicationSecretImport(work, tenantID, idempotencyKey,
				keyDigest, binding, req, names)
		})
	})
}

func applicationSecretImportNames(req secretImportRequest) ([]string, error) {
	if len(req.Values) == 0 || len(req.Values) > 100 {
		return nil, errors.New("values must contain between 1 and 100 secrets")
	}
	if req.Prefix != "" && !validApplicationSecretImportPath(req.Prefix) {
		return nil, errors.New("prefix must be a relative secret path without empty or dot segments")
	}
	names := make([]string, 0, len(req.Values))
	for key, value := range req.Values {
		if !validApplicationSecretImportPath(key) || len(value) == 0 || len(value) > 65536 {
			return nil, errors.New("each import key must be a relative secret path with a nonempty value of at most 65536 bytes")
		}
		name := key
		if req.Prefix != "" {
			name = req.Prefix + "/" + key
		}
		if len(name) > 512 {
			return nil, errors.New("imported secret name exceeds 512 bytes")
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return names, nil
}

func validApplicationSecretImportPath(path string) bool {
	if path == "" || strings.TrimSpace(path) != path {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		for _, character := range segment {
			if unicode.IsControl(character) {
				return false
			}
		}
	}
	return true
}

func (a *API) executeApplicationSecretImport(
	ctx context.Context, tenantID, idempotencyKey, keyDigest, binding string,
	req secretImportRequest, names []string,
) (int, any, error) {
	if a.secrets.be.Store == nil || a.secrets.be.EventLog == nil || a.secrets.be.CommandMAC == nil {
		return 0, nil, errors.New("api: event-sourced application-secret import is unavailable")
	}
	epoch, err := a.applicationSecretTenantEpoch(ctx, tenantID)
	if err != nil {
		return 0, nil, err
	}
	eventID := googleuuid.NewSHA1(applicationSecretImportNamespace,
		[]byte(tenantID+"\x00"+epoch+"\x00"+keyDigest)).String()
	if receipt, err := a.secrets.be.Store.GetApplicationSecretImportReceipt(ctx, tenantID, eventID); err == nil {
		if !crypto.ConstantTimeEqual([]byte(receipt.RequestBinding), []byte(binding)) {
			return 0, nil, applicationSecretMutationError(store.ErrIdempotencyConflict)
		}
		return http.StatusCreated, secretImportResponse{BatchID: receipt.EventID,
			Count: len(receipt.Items), Items: receipt.Items}, nil
	} else if !store.IsNotFound(err) {
		return 0, nil, err
	}
	batch, err := a.secrets.be.Store.GetApplicationSecretImportBatch(ctx, tenantID, eventID)
	if err == nil {
		if !crypto.ConstantTimeEqual([]byte(batch.RequestBinding), []byte(binding)) ||
			!slices.Equal(batch.Names, names) {
			return 0, nil, applicationSecretMutationError(store.ErrIdempotencyConflict)
		}
	} else if store.IsNotFound(err) {
		if err := usage.AllowCreateCount(ctx, tenantID, usage.MeterSecretsStored, len(names)); err != nil {
			return 0, nil, err
		}
		evidence, err := a.applicationSecretImportCommandEvidence(req, tenantID, epoch, idempotencyKey)
		if err != nil {
			return 0, nil, err
		}
		payload := projections.ApplicationSecretBatchImport{
			TenantEpoch: epoch, IdempotencyKeyDigest: keyDigest,
			RequestBinding: binding, CommandEvidence: evidence, Surface: "native",
			Items: make([]projections.ApplicationSecretBatchImportItem, 0, len(names)),
		}
		for _, name := range names {
			key := name
			if req.Prefix != "" {
				key = strings.TrimPrefix(name, req.Prefix+"/")
			}
			sealed, sealErr := a.secrets.seal(ctx, tenantID, []byte(req.Values[key]), sealAAD(tenantID, name))
			if sealErr != nil {
				return 0, nil, sealErr
			}
			payload.Items = append(payload.Items, projections.ApplicationSecretBatchImportItem{Name: name, Sealed: sealed})
		}
		raw, marshalErr := json.Marshal(payload)
		if marshalErr != nil {
			return 0, nil, marshalErr
		}
		actor := applicationSecretActorFromContext(ctx)
		if actor == nil {
			secret.Wipe(raw)
			return 0, nil, errStatus(http.StatusUnauthorized, "an authenticated import actor is required")
		}
		batch = store.ApplicationSecretImportBatch{
			TenantID: tenantID, EventID: eventID, TenantEpoch: epoch, RequestBinding: binding,
			Payload: raw, Actor: actor, EventTime: time.Now().UTC(), Names: names,
		}
	} else {
		return 0, nil, err
	}
	defer secret.Wipe(batch.Payload)
	err = a.secrets.be.Store.RunApplicationSecretImportCommand(ctx, batch, func(barrierCtx context.Context, batch store.ApplicationSecretImportBatch) error {
		event := events.Event{ID: eventID, Type: projections.EventApplicationSecretBatchImported,
			TenantID: tenantID, Time: batch.EventTime,
			SchemaVersion: projections.ApplicationSecretBatchImportSchemaVersion,
			Data:          batch.Payload, Actor: batch.Actor}
		event, err := a.appendApplicationSecretImportEvent(barrierCtx, event)
		if err != nil {
			return err
		}
		projector := projections.New(a.secrets.be.Store)
		return a.secrets.be.Store.WithTenant(barrierCtx, tenantID, func(tx pgx.Tx) error {
			return projector.ApplyTx(barrierCtx, tx, event)
		})
	})
	if err != nil {
		return 0, nil, applicationSecretMutationError(err)
	}
	receipt, err := a.secrets.be.Store.GetApplicationSecretImportReceipt(ctx, tenantID, eventID)
	if err != nil {
		return 0, nil, err
	}
	return http.StatusCreated, secretImportResponse{BatchID: eventID,
		Count: len(receipt.Items), Items: receipt.Items}, nil
}

func (a *API) applicationSecretImportCommandEvidence(
	req secretImportRequest, tenantID, epoch, idempotencyKey string,
) (string, error) {
	material, err := json.Marshal(struct {
		TenantID       string              `json:"tenant_id"`
		TenantEpoch    string              `json:"tenant_epoch"`
		IdempotencyKey string              `json:"idempotency_key_sha256"`
		Request        secretImportRequest `json:"request"`
	}{TenantID: tenantID, TenantEpoch: epoch,
		IdempotencyKey: crypto.SHA256Hex([]byte(idempotencyKey)), Request: req})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(material)
	mac, err := a.secrets.be.CommandMAC([]byte("trstctl.api.application-secret-batch-import.v1"), material)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(mac)
	if len(mac) != 32 {
		return "", errors.New("api: application-secret batch import MAC has invalid length")
	}
	return hex.EncodeToString(mac), nil
}

func (a *API) appendApplicationSecretImportEvent(ctx context.Context, candidate events.Event) (events.Event, error) {
	if prior, found, err := a.secrets.be.EventLog.EventByID(ctx, candidate.ID); err != nil {
		return events.Event{}, err
	} else if found {
		if !sameApplicationSecretImportEvent(prior, candidate) {
			return events.Event{}, store.ErrIdempotencyConflict
		}
		return prior, nil
	}
	canonical, err := a.secrets.be.EventLog.Append(ctx, candidate)
	if err != nil {
		return events.Event{}, err
	}
	if !sameApplicationSecretImportEvent(canonical, candidate) {
		return events.Event{}, store.ErrIdempotencyConflict
	}
	return canonical, nil
}

func sameApplicationSecretImportEvent(a, b events.Event) bool {
	return a.ID == b.ID && a.Type == b.Type && a.TenantID == b.TenantID &&
		a.Time.UTC().Truncate(time.Microsecond).Equal(b.Time.UTC().Truncate(time.Microsecond)) &&
		a.SchemaVersion == b.SchemaVersion &&
		bytes.Equal(a.Data, b.Data) && reflect.DeepEqual(a.Actor, b.Actor)
}

// The startup and periodic application-secret worker uses the durable batch
// table, not a full-history scan. A crash after name reservation or broker
// append is completed from the exact sealed command and actor saved before it.
func (a *API) reconcileApplicationSecretImportBatches(ctx context.Context, tenants []store.Tenant) (int, error) {
	completed := 0
	for _, tenant := range tenants {
		after := ""
		for {
			batches, err := a.secrets.be.Store.ListApplicationSecretImportBatchesPage(
				ctx, tenant.TenantID, after, 100)
			if err != nil {
				return completed, err
			}
			for _, batch := range batches {
				err := a.secrets.be.Store.WithApplicationSecretMutationPrivacyBarrier(
					ctx, tenant.TenantID, func(barrierCtx context.Context) error {
						event, err := a.appendApplicationSecretImportEvent(barrierCtx, events.Event{
							ID: batch.EventID, Type: projections.EventApplicationSecretBatchImported,
							TenantID: tenant.TenantID, Time: batch.EventTime,
							SchemaVersion: projections.ApplicationSecretBatchImportSchemaVersion,
							Data:          batch.Payload, Actor: batch.Actor,
						})
						if err != nil {
							return err
						}
						projector := projections.New(a.secrets.be.Store)
						return a.secrets.be.Store.WithTenant(barrierCtx, tenant.TenantID,
							func(tx pgx.Tx) error { return projector.ApplyTx(barrierCtx, tx, event) })
					})
				if err != nil {
					return completed, err
				}
				completed++
			}
			if len(batches) < 100 {
				break
			}
			after = batches[len(batches)-1].EventID
		}
	}
	return completed, nil
}
