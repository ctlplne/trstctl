// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Tenant self-service KMIP clients (A197). A tenant registers a client and gets
// a one-time enrollment secret; the client's first KMIP request presents its
// TLS certificate with the registration's identifier and the secret as KMIP
// username and password, which binds that certificate to the tenant. The
// handshake proves the client holds the certificate's key and the secret proves
// the tenant sent it, so no tenant can claim a client by registering a
// certificate it has only seen.

// KMIPEnrollmentLifetime is how long an enrollment secret stays usable.
const KMIPEnrollmentLifetime = 24 * time.Hour

const kmipEnrollmentSecretBytes = 32

var kmipClientIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ErrKMIPClientInvalid is a registration request the server refuses.
var ErrKMIPClientInvalid = errors.New("orchestrator: KMIP client registration is invalid")

// ErrKMIPClientNotFound is a registration the tenant does not have.
var ErrKMIPClientNotFound = errors.New("orchestrator: KMIP client not found")

// ErrKMIPEnrollmentRefused is an enrollment the server refuses; the reason is
// for the server's log, never for the client.
var ErrKMIPEnrollmentRefused = errors.New("orchestrator: KMIP enrollment refused")

// KMIPClientEnrollment is a registration with the enrollment secret just
// issued for it. Secret is base64url text the caller shows once and wipes.
type KMIPClientEnrollment struct {
	Client    store.KMIPClient
	Secret    []byte
	ExpiresAt time.Time
}

func newKMIPEnrollmentSecret() ([]byte, string, error) {
	raw, err := crypto.RandomBytes(kmipEnrollmentSecretBytes)
	if err != nil {
		return nil, "", err
	}
	defer secret.Wipe(raw)
	text := make([]byte, base64.RawURLEncoding.EncodedLen(len(raw)))
	base64.RawURLEncoding.Encode(text, raw)
	return text, crypto.SHA256Hex(text), nil
}

func validKMIPClientName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for _, r := range name {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func actorSubject(ctx context.Context) string {
	if actor, ok := events.ActorFromContext(ctx); ok {
		return actor.Subject
	}
	return ""
}

// RegisterKMIPClient records a new KMIP client and returns its enrollment
// secret, which is never stored: only its SHA-256 is.
func (o *Orchestrator) RegisterKMIPClient(ctx context.Context, tenantID, name string) (KMIPClientEnrollment, error) {
	name = strings.TrimSpace(name)
	if !validKMIPClientName(name) {
		return KMIPClientEnrollment{}, fmt.Errorf("%w: name must be 1 to 128 printable characters", ErrKMIPClientInvalid)
	}
	text, hash, err := newKMIPEnrollmentSecret()
	if err != nil {
		return KMIPClientEnrollment{}, err
	}
	expires := time.Now().UTC().Add(KMIPEnrollmentLifetime).Truncate(time.Second)
	id := uuid.NewString()
	payload, err := json.Marshal(projections.KMIPClientRegistered{
		ID: id, Name: name, EnrollmentHash: hash, EnrollmentExpiresAt: expires, RegisteredBy: actorSubject(ctx),
	})
	if err != nil {
		secret.Wipe(text)
		return KMIPClientEnrollment{}, err
	}
	if _, err := o.emit(ctx, projections.EventKMIPClientRegistered, tenantID, payload); err != nil {
		secret.Wipe(text)
		return KMIPClientEnrollment{}, err
	}
	client, found, err := o.store.KMIPClient(ctx, tenantID, id)
	if err != nil || !found {
		secret.Wipe(text)
		return KMIPClientEnrollment{}, errors.Join(ErrKMIPClientNotFound, err)
	}
	return KMIPClientEnrollment{Client: client, Secret: text, ExpiresAt: expires}, nil
}

// IssueKMIPClientEnrollment issues a registration a new enrollment secret, for
// a client that moves to a new certificate. The bound certificate keeps working
// until the new one enrolls.
func (o *Orchestrator) IssueKMIPClientEnrollment(ctx context.Context, tenantID, id string) (KMIPClientEnrollment, error) {
	client, found, err := o.store.KMIPClient(ctx, tenantID, strings.TrimSpace(id))
	if err != nil {
		return KMIPClientEnrollment{}, err
	}
	if !found {
		return KMIPClientEnrollment{}, ErrKMIPClientNotFound
	}
	text, hash, err := newKMIPEnrollmentSecret()
	if err != nil {
		return KMIPClientEnrollment{}, err
	}
	expires := time.Now().UTC().Add(KMIPEnrollmentLifetime).Truncate(time.Second)
	payload, err := json.Marshal(projections.KMIPClientEnrollmentIssued{
		ID: client.ID, EnrollmentHash: hash, EnrollmentExpiresAt: expires, IssuedBy: actorSubject(ctx),
	})
	if err != nil {
		secret.Wipe(text)
		return KMIPClientEnrollment{}, err
	}
	if _, err := o.emit(ctx, projections.EventKMIPClientEnrollmentIssued, tenantID, payload); err != nil {
		secret.Wipe(text)
		return KMIPClientEnrollment{}, err
	}
	client.EnrollmentHash, client.EnrollmentExpiresAt = hash, &expires
	return KMIPClientEnrollment{Client: client, Secret: text, ExpiresAt: expires}, nil
}

// RemoveKMIPClient removes a registration; its certificate is refused from
// its next KMIP request.
func (o *Orchestrator) RemoveKMIPClient(ctx context.Context, tenantID, id string) error {
	client, found, err := o.store.KMIPClient(ctx, tenantID, strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if !found {
		return ErrKMIPClientNotFound
	}
	payload, err := json.Marshal(projections.KMIPClientRemoved{ID: client.ID, RemovedBy: actorSubject(ctx)})
	if err != nil {
		return err
	}
	_, err = o.emit(ctx, projections.EventKMIPClientRemoved, tenantID, payload)
	return err
}

// KMIPClientTenant returns the tenant a certificate is bound to, if any.
func (o *Orchestrator) KMIPClientTenant(ctx context.Context, certDER []byte) (string, bool, error) {
	client, found, err := o.store.KMIPClientByFingerprint(ctx, crypto.SHA256Hex(certDER))
	if err != nil || !found {
		return "", false, err
	}
	return client.TenantID, true, nil
}

// EnrollKMIPClient binds the certificate a KMIP client presented to the
// registration it named, when the secret matches the pending enrollment, and
// returns the registration's tenant. The certificate must be a client
// certificate inside its validity period, not a CA, and not bound to another
// registration.
func (o *Orchestrator) EnrollKMIPClient(ctx context.Context, clientID string, enrollmentSecret, certDER []byte) (string, error) {
	refuse := func(reason string) (string, error) {
		return "", fmt.Errorf("%w: %s", ErrKMIPEnrollmentRefused, reason)
	}
	if !kmipClientIDPattern.MatchString(clientID) {
		return refuse("the username is not a KMIP client registration")
	}
	client, found, err := o.store.KMIPClientForEnrollment(ctx, clientID)
	if err != nil {
		return "", err
	}
	if !found {
		return refuse("no such KMIP client registration")
	}
	now := time.Now().UTC()
	if client.EnrollmentHash == "" || client.EnrollmentExpiresAt == nil || !now.Before(*client.EnrollmentExpiresAt) {
		return refuse("the registration has no unexpired enrollment; issue a new one")
	}
	if !crypto.ConstantTimeEqual([]byte(crypto.SHA256Hex(enrollmentSecret)), []byte(client.EnrollmentHash)) {
		return refuse("the enrollment secret does not match")
	}
	info, err := certinfo.Inspect(certDER)
	if err != nil {
		return refuse("the client certificate does not parse")
	}
	if info.IsCA || now.Before(info.NotBefore) || !now.Before(info.NotAfter) {
		return refuse("the client certificate is a CA or outside its validity period")
	}
	if len(info.ExtKeyUsages) > 0 && !containsString(info.ExtKeyUsages, "clientAuth") && !containsString(info.ExtKeyUsages, "any") {
		return refuse("the client certificate's extended key usage does not allow client authentication")
	}
	if bound, found, err := o.store.KMIPClientByFingerprint(ctx, info.SHA256Fingerprint); err != nil {
		return "", err
	} else if found && (bound.TenantID != client.TenantID || bound.ID != client.ID) {
		return refuse("the client certificate is bound to another KMIP client")
	}
	payload, err := json.Marshal(projections.KMIPClientEnrolled{
		ID: client.ID, Fingerprint: info.SHA256Fingerprint, Subject: info.Subject, NotAfter: info.NotAfter.UTC(),
	})
	if err != nil {
		return "", err
	}
	if _, err := o.emit(ctx, projections.EventKMIPClientEnrolled, client.TenantID, payload); err != nil {
		return "", err
	}
	return client.TenantID, nil
}
