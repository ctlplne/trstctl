// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

const (
	// Frames remain below the signer's existing 1 MiB gRPC receive limit.
	gatedDestroyEvidenceChunkBytes = 128 << 10
	// Public evidence is streamed to an unlinked local file, not held in key
	// process memory. The hard cap and two-stream bulkhead bound disk and CPU.
	gatedDestroyEvidenceMaxBytes = 512 << 20
)

// GatedDestroyStream receives public evidence in bounded frames. The temporary
// file is unlinked before receiving any bytes, so a crash cannot leave a
// plaintext evidence spool on disk. The signer hashes its exact bytes before
// asking the attached gate to verify them; no key operation precedes the gate.
func (s *Server) GatedDestroyStream(stream signerpb.SignerService_GatedDestroyStreamServer) error {
	if s.gatedDestroyStreams == nil || !s.gatedDestroyStreams.tryAcquire() {
		return status.Error(codes.ResourceExhausted, "gated destruction evidence stream at capacity")
	}
	defer s.gatedDestroyStreams.release()
	ctx := stream.Context()
	first, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "missing gated destruction stream header: %v", err)
	}
	if first.GetRequest() == nil || len(first.GetEvidenceChunk()) != 0 || len(first.GetRequest().GetSatisfactionEvidence()) != 0 {
		return status.Error(codes.InvalidArgument, "first frame must contain only command metadata")
	}
	req, err := gatedDestroyRequestFromProto(first.GetRequest())
	if err != nil {
		return err
	}
	spool, err := os.CreateTemp("", "trstctl-gated-destroy-evidence-")
	if err != nil {
		return status.Errorf(codes.Internal, "create bounded evidence spool: %v", err)
	}
	defer func() { _ = spool.Close() }()
	if err := os.Remove(spool.Name()); err != nil {
		return status.Errorf(codes.Internal, "unlink evidence spool: %v", err)
	}
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return status.Error(codes.Canceled, "gated destruction stream canceled")
		}
		frame, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		chunk := frame.GetEvidenceChunk()
		if frame.GetRequest() != nil || len(chunk) == 0 || len(chunk) > gatedDestroyEvidenceChunkBytes {
			return status.Error(codes.InvalidArgument, "invalid gated destruction evidence frame")
		}
		total += int64(len(chunk))
		if total > gatedDestroyEvidenceMaxBytes {
			return status.Error(codes.ResourceExhausted, "gated destruction evidence exceeds bounded stream limit")
		}
		if _, err := spool.Write(chunk); err != nil {
			return status.Errorf(codes.Internal, "write evidence spool: %v", err)
		}
	}
	if total == 0 {
		return status.Error(codes.InvalidArgument, "missing gated destruction evidence")
	}
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		return status.Errorf(codes.Internal, "rewind evidence spool: %v", err)
	}
	digest := crypto.NewSHA256HMACDigest(nil)
	if _, err := io.Copy(digest, spool); err != nil {
		return status.Errorf(codes.Internal, "hash evidence spool: %v", err)
	}
	req.SatisfactionEvidenceDigest = digest.SHA256Sum()
	if _, err := spool.Seek(0, io.SeekStart); err != nil {
		return status.Errorf(codes.Internal, "rewind verified evidence: %v", err)
	}
	decision, err := s.gatedDestroyWithEvidence(ctx, req, spool, s.destroyGatedKeyHandle, true)
	if err != nil {
		if errors.Is(err, ErrNoGatedDestroyer) {
			return status.Error(codes.Unimplemented, err.Error())
		}
		return status.Errorf(codes.FailedPrecondition, "gated destroy stream: %v", err)
	}
	if err := stream.SendAndClose(&signerpb.GatedDestroyStreamResponse{
		Decision: gatedDestroyDecisionToProto(decision),
	}); err != nil {
		return fmt.Errorf("send gated destruction result: %w", err)
	}
	return nil
}

// Send the existing command fields once and the evidence in fixed frames.
// The client never raises the signer's per-message receive limit.
func (c *Client) gatedDestroyStream(ctx context.Context, req GatedDestroyRequest) (GatedDestroyDecision, error) {
	stream, err := c.svc.GatedDestroyStream(ctx)
	if err != nil {
		return GatedDestroyDecision{}, err
	}
	metadata := req
	metadata.SatisfactionEvidence = nil
	if err := stream.Send(&signerpb.GatedDestroyStreamRequest{Request: gatedDestroyRequestToProto(metadata)}); err != nil {
		return GatedDestroyDecision{}, err
	}
	for offset := 0; offset < len(req.SatisfactionEvidence); offset += gatedDestroyEvidenceChunkBytes {
		end := offset + gatedDestroyEvidenceChunkBytes
		if end > len(req.SatisfactionEvidence) {
			end = len(req.SatisfactionEvidence)
		}
		if err := stream.Send(&signerpb.GatedDestroyStreamRequest{
			EvidenceChunk: req.SatisfactionEvidence[offset:end],
		}); err != nil {
			return GatedDestroyDecision{}, err
		}
	}
	response, err := stream.CloseAndRecv()
	if err != nil {
		return GatedDestroyDecision{}, err
	}
	return gatedDestroyDecisionFromProto(response.GetDecision()), nil
}
