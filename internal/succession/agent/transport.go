// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/agent/cosignpb"
)

// transport.go carries the workload-agent co-sign RPC (PCAS-claim-19, INT-16): the
// platform signer/orchestrator asks the agent, over a real gRPC transport, to co-sign
// a succession commitment with the predecessor key the agent holds. The wire carries
// the STRUCTURED commitment fields (MarshalFields) — never an opaque digest — so the
// agent reconstructs and domain-separates the commitment itself and the FIG. 5
// oracle-prevention checks run server-side, unchanged, whether a co-sign arrives
// in-process or over the transport. Only the predecessor signature (public) crosses
// back; the predecessor key never leaves the agent.

const fieldsDomain = "trstctl/pcas/workload-cosign/fields/v1"

// ErrFieldsMalformed is returned when a co-sign request's encoded fields do not
// decode to a well-formed commitment-field set.
var ErrFieldsMalformed = errors.New("agent: malformed co-sign commitment-field encoding")

// MarshalFields returns the canonical, reversible encoding of the commitment fields
// carried in a co-sign request. It is lossless: UnmarshalFields(MarshalFields(f))
// reproduces f, so the agent reconstructs the exact commitment the caller intends —
// while still receiving typed, inspectable fields rather than an opaque digest.
func MarshalFields(f succession.CommitmentFields) []byte {
	var b bytes.Buffer
	b.WriteString(fieldsDomain)
	putStr(&b, f.DeploymentScope)
	putStr(&b, f.IdentityID)
	putStr(&b, f.TenantID)
	putU64(&b, f.PredecessorEpoch)
	putU64(&b, f.Epoch)
	putStr(&b, string(f.PredecessorAlg))
	putBytes(&b, f.PredecessorPub)
	putStr(&b, string(f.SuccessorAlg))
	putBytes(&b, f.SuccessorPub)
	putStr(&b, f.PolicyRef)
	putStr(&b, f.HashAlg)
	putI64(&b, f.NotBefore)
	putI64(&b, f.NotAfter)
	putU64(&b, uint64(f.CommitmentVersion))
	putStr(&b, string(f.RecordType))
	putBytes(&b, f.AuthzDigest)
	putBytes(&b, f.AttestationEvidenceDigest)
	putStr(&b, f.AttestationType)
	putStr(&b, f.DelegationPath)
	return b.Bytes()
}

// UnmarshalFields parses the canonical encoding produced by MarshalFields.
func UnmarshalFields(in []byte) (succession.CommitmentFields, error) {
	r := &fieldReader{b: in}
	if !r.expect(fieldsDomain) {
		return succession.CommitmentFields{}, ErrFieldsMalformed
	}
	var f succession.CommitmentFields
	var ok bool
	var s string
	if f.DeploymentScope, ok = r.str(); !ok {
		return bad()
	}
	if f.IdentityID, ok = r.str(); !ok {
		return bad()
	}
	if f.TenantID, ok = r.str(); !ok {
		return bad()
	}
	if f.PredecessorEpoch, ok = r.u64(); !ok {
		return bad()
	}
	if f.Epoch, ok = r.u64(); !ok {
		return bad()
	}
	if s, ok = r.str(); !ok {
		return bad()
	}
	f.PredecessorAlg = crypto.Algorithm(s)
	if f.PredecessorPub, ok = r.bytes(); !ok {
		return bad()
	}
	if s, ok = r.str(); !ok {
		return bad()
	}
	f.SuccessorAlg = crypto.Algorithm(s)
	if f.SuccessorPub, ok = r.bytes(); !ok {
		return bad()
	}
	if f.PolicyRef, ok = r.str(); !ok {
		return bad()
	}
	if f.HashAlg, ok = r.str(); !ok {
		return bad()
	}
	if f.NotBefore, ok = r.i64(); !ok {
		return bad()
	}
	if f.NotAfter, ok = r.i64(); !ok {
		return bad()
	}
	var cv uint64
	if cv, ok = r.u64(); !ok {
		return bad()
	}
	// CommitmentVersion is a uint32 on the wire's 8-byte integer field; anything wider
	// is not a version this build can represent, so fail closed rather than truncate.
	if cv > math.MaxUint32 {
		return bad()
	}
	f.CommitmentVersion = uint32(cv)
	if s, ok = r.str(); !ok {
		return bad()
	}
	f.RecordType = succession.RecordType(s)
	if f.AuthzDigest, ok = r.bytes(); !ok {
		return bad()
	}
	if f.AttestationEvidenceDigest, ok = r.bytes(); !ok {
		return bad()
	}
	if f.AttestationType, ok = r.str(); !ok {
		return bad()
	}
	if f.DelegationPath, ok = r.str(); !ok {
		return bad()
	}
	if len(r.b) != 0 {
		return bad()
	}
	return f, nil
}

func bad() (succession.CommitmentFields, error) {
	return succession.CommitmentFields{}, ErrFieldsMalformed
}

// CoSignServer adapts a CoSigner to the gRPC CoSignerService. It decodes the
// structured fields and delegates to CoSigner.CoSign, so all oracle-prevention checks
// (purpose, own identity/tenant/deployment, own predecessor key, domain-separated
// reconstruction) run exactly as in-process.
type CoSignServer struct {
	cosignpb.UnimplementedCoSignerServiceServer
	cosigner *CoSigner
}

// NewCoSignServer returns a gRPC server for the given co-signer.
func NewCoSignServer(cs *CoSigner) *CoSignServer { return &CoSignServer{cosigner: cs} }

// Register registers the co-sign service on a gRPC server (convenience for the agent
// binary).
func (s *CoSignServer) Register(gs *grpc.Server) { cosignpb.RegisterCoSignerServiceServer(gs, s) }

// CoSign is the gRPC handler. It maps the agent's typed refusals to
// FailedPrecondition so the caller can distinguish an oracle-prevention refusal from
// a transport error, and returns only the predecessor signature.
func (s *CoSignServer) CoSign(_ context.Context, req *cosignpb.CoSignRequest) (*cosignpb.CoSignResponse, error) {
	fields, err := UnmarshalFields(req.GetFields())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	resp, err := s.cosigner.CoSign(Request{Purpose: req.GetPurpose(), Fields: fields})
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	return &cosignpb.CoSignResponse{Signature: resp.Signature}, nil
}

// RemoteCoSigner is the control-plane / orchestrator view of a workload agent reached
// over the transport. It satisfies PredecessorCoSigner, so MintWorkloadHeld drives a
// real co-sign round-trip. It deliberately lives outside the AN-4 signer closure: the
// workload-held mint is orchestrated control-plane-side, and only successor keygen
// happens in the isolated signer.
type RemoteCoSigner struct {
	client cosignpb.CoSignerServiceClient
	ctx    context.Context
}

// NewRemoteCoSigner returns a RemoteCoSigner over an established gRPC connection.
func NewRemoteCoSigner(conn grpc.ClientConnInterface) *RemoteCoSigner {
	return &RemoteCoSigner{client: cosignpb.NewCoSignerServiceClient(conn), ctx: context.Background()}
}

// WithContext returns a copy of the RemoteCoSigner that uses ctx for its RPCs.
func (r *RemoteCoSigner) WithContext(ctx context.Context) *RemoteCoSigner {
	c := *r
	c.ctx = ctx
	return &c
}

// CoSign performs the co-sign RPC and maps a remote oracle-prevention refusal back to
// the corresponding agent sentinel so callers can errors.Is against it.
func (r *RemoteCoSigner) CoSign(req Request) (Response, error) {
	resp, err := r.client.CoSign(r.ctx, &cosignpb.CoSignRequest{Purpose: req.Purpose, Fields: MarshalFields(req.Fields)})
	if err != nil {
		return Response{}, mapRemoteErr(err)
	}
	return Response{Signature: resp.GetSignature()}, nil
}

// mapRemoteErr reconstructs the agent's typed refusal from a gRPC status so a caller
// can match it with errors.Is, while preserving the transport error otherwise.
func mapRemoteErr(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	msg := st.Message()
	for _, sentinel := range []error{ErrForeignPurpose, ErrForeignBinding, ErrNotPredecessor, ErrMalformed, ErrFieldsMalformed} {
		if msg == sentinel.Error() {
			return fmt.Errorf("agent co-sign refused over transport: %w", sentinel)
		}
	}
	return fmt.Errorf("agent co-sign transport error: %w", err)
}

func putU64(b *bytes.Buffer, v uint64) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], v)
	b.Write(n[:])
}

// putI64 writes v as the same 8-byte big-endian two's-complement field putU64 would
// have written for the reinterpreted scalar. Each byte is masked straight out of v,
// so no signed/unsigned conversion happens and the wire format is unchanged.
func putI64(b *bytes.Buffer, v int64) {
	n := [8]byte{
		byte(v >> 56 & 0xFF),
		byte(v >> 48 & 0xFF),
		byte(v >> 40 & 0xFF),
		byte(v >> 32 & 0xFF),
		byte(v >> 24 & 0xFF),
		byte(v >> 16 & 0xFF),
		byte(v >> 8 & 0xFF),
		byte(v & 0xFF),
	}
	b.Write(n[:])
}

func putBytes(b *bytes.Buffer, v []byte) {
	putU64(b, uint64(len(v)))
	b.Write(v)
}

func putStr(b *bytes.Buffer, s string) { putBytes(b, []byte(s)) }

type fieldReader struct{ b []byte }

func (r *fieldReader) expect(s string) bool {
	if len(r.b) < len(s) || string(r.b[:len(s)]) != s {
		return false
	}
	r.b = r.b[len(s):]
	return true
}

func (r *fieldReader) u64() (uint64, bool) {
	if len(r.b) < 8 {
		return 0, false
	}
	v := binary.BigEndian.Uint64(r.b[:8])
	r.b = r.b[8:]
	return v, true
}

// i64 reads the 8-byte big-endian two's-complement field written by putI64. The value
// is accumulated byte by byte (each byte widens cleanly to int64), which is
// bit-identical to reinterpreting the big-endian unsigned read as int64 but performs
// no narrowing or sign-reinterpreting conversion.
func (r *fieldReader) i64() (int64, bool) {
	if len(r.b) < 8 {
		return 0, false
	}
	var v int64
	for _, c := range r.b[:8] {
		v = v<<8 | int64(c)
	}
	r.b = r.b[8:]
	return v, true
}

func (r *fieldReader) bytes() ([]byte, bool) {
	n, ok := r.u64()
	if !ok || n > uint64(len(r.b)) {
		return nil, false
	}
	out := make([]byte, n)
	copy(out, r.b[:n])
	r.b = r.b[n:]
	return out, true
}

func (r *fieldReader) str() (string, bool) {
	v, ok := r.bytes()
	return string(v), ok
}
