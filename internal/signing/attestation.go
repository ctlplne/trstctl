package signing

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// Dual-control sign-intent attestation (RED-003).
//
// The forge-the-fleet residual is that the signer signs an arbitrary
// attacker-chosen digest: with the issuing-CA handle and the right purpose, a
// principal on the socket can have the CA key sign sha256(<any attacker TBS>).
// Per-key purpose/algorithm constraints (SIGNER-002/003) bound WHICH key class is
// usable but not WHAT content is signed. This file adds the cheap signer-side
// defense that bounds the content for the crown-jewel key classes: a key may be
// marked DUAL-CONTROL, and the signer then refuses any Sign against it unless the
// request carries a valid authorization token — an HMAC over the EXACT signing
// tuple, produced by an approval authority holding a secret the on-socket caller
// does not. The token commits to the digest, so it authorizes one specific
// to-be-signed object and cannot be replayed onto different bytes; absent the
// approver secret, socket access can no longer coerce the key into forging trust.
//
// Because the wire proto is frozen (it already ships generated and CODEOWNERS-
// protected), the dual-control opt-in and the per-Sign token travel as gRPC
// metadata, not new message fields — additive, wire-compatible, and the
// conventional place for an out-of-band authorization token. The crypto lives
// behind internal/crypto (AN-3); the signer holds a verify-only authorizer.

const (
	// mdRequireAuth is the GenerateKey metadata flag that marks the new key
	// dual-control. Any non-empty value with the signer configured for
	// dual-control turns it on. (A key cannot be marked dual-control if the signer
	// has no authorizer — that would brick it.)
	mdRequireAuth = "trstctl-sign-require-auth"
	// mdSignAuthToken is the Sign metadata key carrying the base64-of-raw
	// authorization token bytes for a dual-control key. (gRPC metadata is ASCII
	// for non "-bin" keys; a "-bin" suffix lets us send raw bytes.)
	mdSignAuthToken = "trstctl-sign-auth-token-bin"
)

// requireAuthFromGenerateMD reports whether the GenerateKey call asked for a
// dual-control key (via metadata). It is independent of the proto so the wire
// contract is untouched.
func requireAuthFromGenerateMD(ctx context.Context) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	for _, v := range md.Get(mdRequireAuth) {
		if v != "" {
			return true
		}
	}
	return false
}

// signAuthTokenFromMD extracts the raw authorization token bytes a Sign carries in
// metadata, or nil when none is present.
func signAuthTokenFromMD(ctx context.Context) []byte {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil
	}
	vals := md.Get(mdSignAuthToken)
	if len(vals) == 0 {
		return nil
	}
	// gRPC decodes a "-bin" header's base64 into the raw string on the way in.
	return []byte(vals[0])
}

// intentFor builds the SignIntent the authorization must match: every field that
// influences the produced signature, so a token authorizes exactly this operation.
// It is the SINGLE canonicalization used by BOTH the minting side (the
// RemoteSigner client) and the verifying side (this server), derived from the wire
// request, so the two intents are byte-equal regardless of how the caller left
// zero-valued options. A change here must change both sides at once.
func intentFor(req *signerpb.SignRequest) crypto.SignIntent {
	return crypto.SignIntent{
		KeyHandle: req.GetHandle().GetId(),
		Purpose:   int32(req.GetPurpose()),
		Hash:      mustHashForIntent(req.GetHash()),
		Padding:   paddingFromProto(req.GetRsaPadding()),
		Digest:    req.GetDigest(),
	}
}

// mustHashForIntent maps the proto hash to the crypto.Hash used in the intent. The
// request is shape-validated before this runs, so the hash is one of the three
// supported values; an unexpected value maps to SHA256 only for the intent's
// canonicalization (the real sign still rejects an unsupported hash upstream).
func mustHashForIntent(h signerpb.Hash) crypto.Hash {
	ch, _, err := hashFromProto(h)
	if err != nil {
		return crypto.SHA256
	}
	return ch
}

// enforceDualControl is called by Sign for a key whose constraints require an
// authorization. It fails closed: a signer with no authorizer configured cannot
// honor a dual-control key (returns FailedPrecondition); a missing or invalid
// token returns PermissionDenied. On success the digest, purpose, hash and handle
// were all attested by the approval authority.
func (s *Server) enforceDualControl(ctx context.Context, req *signerpb.SignRequest) error {
	if s.authorizer == nil {
		return status.Error(codes.FailedPrecondition,
			"key requires dual-control authorization but this signer has no authorizer configured")
	}
	token := signAuthTokenFromMD(ctx)
	if len(token) == 0 {
		return status.Error(codes.PermissionDenied,
			"key requires a dual-control authorization token; none was presented")
	}
	if !s.authorizer.Verify(intentFor(req), token) {
		return status.Error(codes.PermissionDenied,
			"dual-control authorization token is invalid for this signing request")
	}
	return nil
}
