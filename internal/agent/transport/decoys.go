// SPDX-License-Identifier: BUSL-1.1

package transport

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Q6-O1: a host agent plants decoy files — SSH private keys written where no
// file was and authorized nowhere — and reports them, and every open of them,
// over the channel. Decoys go to the decoy registry, readable by those who may
// plant decoys, never to the host inventory every reader sees. Neither message
// can carry a private key: a decoy travels as its public half.

const (
	// DecoyReportMaxDecoys bounds the decoys one report carries.
	DecoyReportMaxDecoys = 64
	// DecoyReportMaxOpens bounds the opens one report carries.
	DecoyReportMaxOpens = 256
	// DecoyPathMaxBytes bounds a decoy file's path.
	DecoyPathMaxBytes = 1024
	// DecoyPublicKeyMaxBytes bounds a decoy key's public half.
	DecoyPublicKeyMaxBytes = 1024
	// DecoyProcessMaxBytes bounds an opening program's name.
	DecoyProcessMaxBytes = 256
)

// DecoyFile is one decoy the agent planted: its absolute path and the public
// half of the decoy key in authorized_keys form.
type DecoyFile struct {
	Path      string    `json:"path"`
	PublicKey string    `json:"public_key"`
	PlantedAt time.Time `json:"planted_at"`
}

// DecoyOpen is one open of a decoy file the agent saw.
type DecoyOpen struct {
	Path string    `json:"path"`
	At   time.Time `json:"at"`
	// PID and Process name the opener when the watcher could see it
	// (fanotify, or a process still holding the file under inotify).
	PID     int    `json:"pid,omitempty"`
	Process string `json:"process,omitempty"`
	// Mechanism is how the agent saw the open: "fanotify" or "inotify".
	Mechanism string `json:"mechanism,omitempty"`
}

// DecoyReportRequest carries decoys the agent planted and opens it saw. The
// host is the channel certificate's name, never a field.
type DecoyReportRequest struct {
	Decoys []DecoyFile `json:"decoys,omitempty"`
	Opens  []DecoyOpen `json:"opens,omitempty"`
}

// DecoyReportResponse counts what the control plane did with a report.
type DecoyReportResponse struct {
	TenantID string `json:"tenant_id"`
	// Registered counts decoys new to the control plane; Known, decoys it
	// already held.
	Registered int `json:"registered"`
	Known      int `json:"known"`
	// Recorded counts opens recorded against a live decoy; Rejected, opens of
	// a path where this host has none (never registered, or retired).
	Recorded int `json:"recorded"`
	Rejected int `json:"rejected"`
}

// AgentDecoyServiceServer is the optional decoy extension of AgentService
// (Q6-O1), separate so an older service implementation stays
// source-compatible.
type AgentDecoyServiceServer interface {
	ReportDecoys(ctx context.Context, req *DecoyReportRequest) (*DecoyReportResponse, error)
}

const (
	methodReportDecoys     = "ReportDecoys"
	fullMethodReportDecoys = "/" + agentServiceName + "/" + methodReportDecoys
)

func reportDecoysHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(DecoyReportRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	decoys, ok := srv.(AgentDecoyServiceServer)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "this control plane does not accept decoy reports over the agent channel")
	}
	if interceptor == nil {
		return decoys.ReportDecoys(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: fullMethodReportDecoys}
	handler := func(ctx context.Context, req any) (any, error) {
		return decoys.ReportDecoys(ctx, req.(*DecoyReportRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ReportDecoys sends the decoys this host's agent planted and the opens it saw
// (Q6-O1).
func (c *AgentClient) ReportDecoys(ctx context.Context, req *DecoyReportRequest) (*DecoyReportResponse, error) {
	out := new(DecoyReportResponse)
	if err := c.cc.Invoke(c.withProtocol(ctx), fullMethodReportDecoys, req, out, grpc.CallContentSubtype(AgentCodecName)); err != nil {
		return nil, err
	}
	return out, nil
}
