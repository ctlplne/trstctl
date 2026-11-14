// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/protocols/est"
	"trstctl.com/trstctl/internal/store"
)

// First boot and renewal for factory-provisioned devices (P12). A device
// enrolls at /.well-known/est/factory/simpleenroll with a proof signed by its
// birth key, and renews at .../simplereenroll with one signed by its current
// operational key. The proof rides in the Authorization header, so it crosses
// the relay enrollment proxy unchanged where the device has no route: a TLS
// client certificate would not. It is a JWT whose kid is the SHA-256 of the
// certificate that signs it and whose claims name the device, the purpose and
// the SHA-256 of the exact CSR, within five minutes of now.

const (
	factoryPurposeFirstBoot = "trstctl-factory-first-boot"
	factoryPurposeRenewal   = "trstctl-factory-renewal"
	factoryProofWindow      = 5 * time.Minute
	factoryMaxCSRBody       = 64 << 10
)

// FactoryProofClaims is what a device signs.
type FactoryProofClaims struct {
	Subject   string `json:"sub"`
	Purpose   string `json:"purpose"`
	CSRSHA256 string `json:"csr_sha256"`
	IssuedAt  int64  `json:"iat"`
}

type factoryProofKey struct{}

// factoryProof is a verified proof on one factory EST request.
type factoryProof struct {
	birth     store.FactoryBirth
	batch     store.FactoryBatch
	renewal   bool
	csrSHA256 string
}

// factoryESTGate verifies the proof on a factory enrollment before the EST
// server sees it and hands the verified birth to its authenticator and
// enroller. Every other EST request passes through untouched.
func (s *Server) factoryESTGate(tenantID string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op, factory := strings.CutPrefix(r.URL.Path, factoryESTPath+"/")
		if !factory || r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		if op != "simpleenroll" && op != "simplereenroll" {
			http.Error(w, "est: the factory profile serves first boot and renewal only", http.StatusNotFound)
			return
		}
		proof, status, err := s.verifyFactoryProof(r, tenantID, op == "simplereenroll")
		if err != nil {
			http.Error(w, "est: "+err.Error(), status)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), factoryProofKey{}, proof)))
	})
}

// factoryProofKeyID reads the kid from a compact JWT's header without trusting
// anything else in it; the signature is checked against the certificate the
// kid names.
func factoryProofKeyID(token string) string {
	header, _, ok := strings.Cut(token, ".")
	if !ok {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return ""
	}
	var h struct {
		Kid string `json:"kid"`
	}
	if json.Unmarshal(raw, &h) != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(h.Kid))
}

func (s *Server) verifyFactoryProof(r *http.Request, tenantID string, renewal bool) (factoryProof, int, error) {
	ctx := r.Context()
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	kid := factoryProofKeyID(token)
	if !ok || kid == "" {
		return factoryProof{}, http.StatusUnauthorized, errors.New("a factory enrollment needs the device's signed proof")
	}
	birth, found, err := s.store.FactoryBirthByFingerprint(ctx, tenantID, kid, renewal)
	if err != nil {
		return factoryProof{}, http.StatusInternalServerError, errors.New("the device's birth record could not be read")
	}
	if !found {
		if renewal {
			return factoryProof{}, http.StatusUnauthorized, errors.New("the proof names no operational certificate of a factory device")
		}
		return factoryProof{}, http.StatusUnauthorized, errors.New("the proof names no birth certificate a station's journal reconciled")
	}
	signingCert := birth.CertificateDER
	purpose := factoryPurposeFirstBoot
	if renewal {
		signingCert, purpose = birth.OperationalDER, factoryPurposeRenewal
	}
	publicDER, err := crypto.PublicKeyDERFromCert(signingCert)
	if err != nil {
		return factoryProof{}, http.StatusUnauthorized, errors.New("the proof's certificate has no usable key")
	}
	jwk, err := crypto.PublicJWK(crypto.PublicKey{DER: publicDER}, kid)
	if err != nil {
		return factoryProof{}, http.StatusUnauthorized, errors.New("the proof's certificate has no usable key")
	}
	claimsJSON, err := crypto.VerifyJWT(token, crypto.JWKS{Keys: []crypto.JWK{jwk}})
	if err != nil {
		return factoryProof{}, http.StatusUnauthorized, errors.New("the proof is not signed by that certificate's key")
	}
	var claims FactoryProofClaims
	if json.Unmarshal(claimsJSON, &claims) != nil || claims.Purpose != purpose || !strings.EqualFold(claims.Subject, birth.DeviceName) {
		return factoryProof{}, http.StatusUnauthorized, errors.New("the proof is for another device or purpose")
	}
	if age := time.Since(time.Unix(claims.IssuedAt, 0)); age > factoryProofWindow || age < -factoryProofWindow {
		return factoryProof{}, http.StatusUnauthorized, errors.New("the proof is not from the last five minutes")
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, factoryMaxCSRBody+1))
	if err != nil || len(raw) > factoryMaxCSRBody {
		return factoryProof{}, http.StatusRequestEntityTooLarge, errors.New("request body too large")
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	csrDER, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(raw)), ""))
	if err != nil {
		return factoryProof{}, http.StatusBadRequest, errors.New("the body is not a base64 PKCS#10 request")
	}
	digest := crypto.SHA256Hex(csrDER)
	if !strings.EqualFold(digest, claims.CSRSHA256) {
		return factoryProof{}, http.StatusUnauthorized, errors.New("the proof is for another request")
	}
	csr, err := crypto.InspectCSR(csrDER)
	if err != nil || !strings.EqualFold(csr.CommonName, birth.DeviceName) || len(csr.IPAddresses) > 0 || len(csr.URIs) > 0 ||
		len(csr.EmailAddresses) > 0 || (len(csr.DNSNames) > 0 && (len(csr.DNSNames) != 1 || !strings.EqualFold(csr.DNSNames[0], birth.DeviceName))) {
		return factoryProof{}, http.StatusForbidden, errors.New("the request must name exactly the device its birth certificate names")
	}
	batch, err := s.store.GetFactoryBatch(ctx, tenantID, birth.BatchID)
	if err != nil {
		return factoryProof{}, http.StatusInternalServerError, errors.New("the device's batch could not be read")
	}
	now := time.Now()
	if !renewal {
		if birth.OverQuota {
			return factoryProof{}, http.StatusForbidden, errors.New("over-production: this birth certificate is past its batch's quota")
		}
		if !birth.NotAfter.After(now) {
			return factoryProof{}, http.StatusForbidden, errors.New("the birth certificate has expired")
		}
		// P12-L1: a batch with device attestation roots enrolls only births
		// whose device attestation the reconcile verified.
		if len(batch.DeviceAttestationRootsPEM) > 0 && birth.Attestation != store.FactoryAttestationVerified {
			return factoryProof{}, http.StatusForbidden, errors.New("the batch requires a verified device attestation of the birth key, and this birth has none")
		}
		d, found, err := s.store.GetEdgeDelegation(ctx, tenantID, batch.DelegationID)
		if err != nil || !found || d.RevokedAt != nil || d.Status == "revoked" {
			return factoryProof{}, http.StatusForbidden, errors.New("the batch's station delegation is revoked")
		}
		delegationDER, err := firstCertDER(d.CertificatePEM)
		if err != nil {
			return factoryProof{}, http.StatusInternalServerError, errors.New("the batch's station delegation could not be read")
		}
		if _, err := crypto.InspectEdgeReportedLeaf(delegationDER, birth.CertificateDER); err != nil {
			return factoryProof{}, http.StatusForbidden, errors.New("the birth certificate does not chain to its batch's station")
		}
		if birth.Enrolled && !strings.EqualFold(birth.CSRSHA256, digest) {
			return factoryProof{}, http.StatusConflict, errors.New("this device already enrolled on first boot; renew with its operational certificate")
		}
	} else {
		if !birth.Enrolled {
			return factoryProof{}, http.StatusForbidden, errors.New("the device has not enrolled")
		}
		current, err := certinfo.Inspect(birth.OperationalDER)
		if err != nil || !current.NotAfter.After(now) {
			return factoryProof{}, http.StatusForbidden, errors.New("the operational certificate has expired")
		}
	}
	return factoryProof{birth: birth, batch: batch, renewal: renewal, csrSHA256: digest}, 0, nil
}

// factoryProofAuth admits exactly the requests the gate verified.
type factoryProofAuth struct{}

func (factoryProofAuth) Authenticate(r *http.Request) est.AuthenticationResult {
	if _, ok := r.Context().Value(factoryProofKey{}).(factoryProof); ok {
		return est.AuthenticationResult{Allowed: true}
	}
	return est.AuthenticationResult{StatusCode: http.StatusUnauthorized}
}

// factoryEnroller issues the operational certificate through the tenant's EST
// issuance and records it on the device's birth record.
type factoryEnroller struct {
	tenantID string
	inner    enrollerAdapter
	server   *Server
}

func (e factoryEnroller) Enroll(ctx context.Context, csrDER []byte, profileName, protocol, idempotencyKey string) ([]byte, error) {
	proof, ok := ctx.Value(factoryProofKey{}).(factoryProof)
	if !ok || e.server == nil || e.server.orch == nil {
		return nil, errors.New("server: a factory enrollment needs a verified proof")
	}
	profile := profileName
	if proof.batch.OperationalProfile != "" {
		profile = proof.batch.OperationalProfile
	}
	leaf, err := e.inner.Enroll(ctx, csrDER, profile, protocol, "factory:"+proof.birth.Serial+":"+idempotencyKey)
	if err != nil {
		return nil, err
	}
	info, err := certinfo.Inspect(leaf)
	if err != nil {
		return nil, err
	}
	enrolled := projections.FactoryDeviceEnrolled{BatchID: proof.birth.BatchID, Serial: proof.birth.Serial,
		OperationalSerial: strings.ToLower(info.SerialNumber), OperationalFingerprint: strings.ToLower(info.SHA256Fingerprint),
		OperationalDER: leaf, Renewal: proof.renewal}
	if !proof.renewal {
		enrolled.CSRSHA256 = proof.csrSHA256
	}
	if err := e.server.orch.RecordFactoryDeviceEnrolled(ctx, e.tenantID, enrolled); err != nil {
		return nil, err
	}
	return leaf, nil
}

// buildFactoryEST is the factory EST profile's server.
func (s *Server) buildFactoryEST(tenantID string, issuer *protocolIssuer, pool *bulkhead.Pool) *est.Server {
	return est.New(est.Config{
		Enroller:     factoryEnroller{tenantID: tenantID, inner: enrollerAdapter{tenantID: tenantID, issuer: issuer}, server: s},
		Auth:         factoryProofAuth{},
		CAChainDER:   [][]byte{s.caCertDER},
		Pool:         pool,
		Log:          s.log,
		CSRVerifier:  issuer.verifyCSR,
		CSRInspector: issuer.inspectCSRInfo,
	})
}
