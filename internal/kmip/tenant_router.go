// SPDX-License-Identifier: BUSL-1.1

package kmip

import (
	"context"
	"errors"
	"log/slog"
	"sync"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// The shared listener's tenants (A197). With protocols.kmip.client_registrations
// on, each request is served for the tenant its client belongs to: the tenant
// that bound the client's certificate with an enrollment, or the configured
// tenant for a client the deployment's client CA issued. A client whose
// certificate is neither enrolls with its request's username and password, the
// enrollment its tenant issued; anything else is refused before an operation
// runs, and the refusal names no tenant.

var errClientNotRecognized = errors.New("the client certificate is not enrolled; send the registration's enrollment username and password")

// tenantServers holds one KMIP server per tenant the listener has served,
// each rebuilt from that tenant's events when first needed.
type tenantServers struct {
	mu      sync.Mutex
	servers map[string]*Server
	open    func(tenantID string) (*Server, error)
}

func (t *tenantServers) get(tenantID string) (*Server, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if s, ok := t.servers[tenantID]; ok {
		return s, nil
	}
	s, err := t.open(tenantID)
	if err != nil {
		return nil, err
	}
	t.servers[tenantID] = s
	return s, nil
}

func (t *tenantServers) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, s := range t.servers {
		s.Close()
	}
	clear(t.servers)
}

// serverFor resolves the KMIP server a request is served by. Without client
// registrations it is the configured tenant's, as before.
func (r *Runtime) serverFor(ctx context.Context, chain [][]byte, frame []byte) (*Server, error) {
	if r.clients == nil {
		return r.service, nil
	}
	tenantID, found, err := r.clients.KMIPClientTenant(ctx, chain[0])
	if err != nil {
		return nil, err
	}
	if !found {
		if r.service != nil && r.clientCAs.Verifies(chain) {
			return r.service, nil
		}
		tenantID, err = r.enroll(ctx, chain[0], frame)
		if err != nil {
			return nil, err
		}
	}
	if r.service != nil && tenantID == r.service.tenantID {
		return r.service, nil
	}
	return r.tenants.get(tenantID)
}

// enroll binds the client's certificate with the credential its request
// carries.
func (r *Runtime) enroll(ctx context.Context, certDER, frame []byte) (string, error) {
	msg, err := DecodeRequestMessage(frame)
	defer secret.Wipe(msg.Password)
	if err != nil || msg.Username == "" {
		return "", errClientNotRecognized
	}
	tenantID, err := r.clients.EnrollKMIPClient(ctx, msg.Username, msg.Password, certDER)
	if err != nil {
		r.log.Warn("KMIP client enrollment refused", slog.String("error", err.Error()))
		return "", errClientNotRecognized
	}
	r.log.Info("KMIP client enrolled", slog.String("tenant_id", tenantID))
	return tenantID, nil
}

// refusedResponse answers every batch item of a request the listener will not
// serve with Authentication Not Successful.
func refusedResponse(frame []byte, reason string) []byte {
	msg, err := DecodeRequestMessage(frame)
	secret.Wipe(msg.Password)
	if err != nil {
		return encodeResponse(1, 2, []wireResponseItem{failureItem(0, resultReasonInvalidMessage, err.Error())})
	}
	items := make([]wireResponseItem, 0, len(msg.BatchItems))
	for _, item := range msg.BatchItems {
		items = append(items, failureItem(item.Operation, resultReasonAuthFailed, reason))
	}
	return encodeResponse(msg.ProtocolMajor, msg.ProtocolMinor, items)
}
