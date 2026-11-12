// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"path"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/sshkeys"
)

// Q6-O1: a host agent plants decoy files — SSH private keys written where no
// file was — and reports them, and every open of them, over the channel. The
// host is the channel certificate's name: an agent registers decoys on its own
// host only, and an open counts against the live decoy at that path on that
// host. Decoys go to the decoy registry, never the host inventory, and each
// program that opens one alerts once (the decoy-secret reader rule).

// ReportDecoys implements transport.AgentDecoyServiceServer.
func (a *agentService) ReportDecoys(ctx context.Context, req *transport.DecoyReportRequest) (*transport.DecoyReportResponse, error) {
	ctx, info, release, err := a.beginPeerWork(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if !agentHasRole(info.Roles, mtls.AgentRoleHost) {
		return nil, status.Error(codes.PermissionDenied, "decoy files are planted by host agents")
	}
	if a.orch == nil {
		return nil, status.Error(codes.FailedPrecondition, "the decoy registry is not configured")
	}
	if _, err := a.store.GetAgent(ctx, info.TenantID, agentRowID(info.TenantID, info.CommonName)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Error(codes.FailedPrecondition, "send an authenticated heartbeat before a decoy report")
		}
		return nil, status.Error(codes.Unavailable, "agent registration state is unavailable; retry later")
	}
	if req == nil || len(req.Decoys)+len(req.Opens) == 0 {
		return nil, status.Error(codes.InvalidArgument, "a decoy report needs at least one decoy or open")
	}
	if len(req.Decoys) > transport.DecoyReportMaxDecoys || len(req.Opens) > transport.DecoyReportMaxOpens {
		return nil, status.Errorf(codes.InvalidArgument, "a decoy report carries at most %d decoys and %d opens",
			transport.DecoyReportMaxDecoys, transport.DecoyReportMaxOpens)
	}
	fingerprints := make([]string, len(req.Decoys))
	for i, d := range req.Decoys {
		if !validDecoyPath(d.Path) {
			return nil, status.Errorf(codes.InvalidArgument, "decoy %d: the path must be absolute, clean and at most %d bytes", i, transport.DecoyPathMaxBytes)
		}
		if d.PublicKey == "" || len(d.PublicKey) > transport.DecoyPublicKeyMaxBytes {
			return nil, status.Errorf(codes.InvalidArgument, "decoy %d: the public key must be 1-%d bytes", i, transport.DecoyPublicKeyMaxBytes)
		}
		key, err := sshkeys.ParsePublicKey([]byte(d.PublicKey))
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "decoy %d: the public key is not an SSH public key in authorized_keys form", i)
		}
		fingerprints[i] = key.FingerprintSHA256
	}
	for i, o := range req.Opens {
		switch {
		case !validDecoyPath(o.Path):
			return nil, status.Errorf(codes.InvalidArgument, "open %d: the path must be absolute, clean and at most %d bytes", i, transport.DecoyPathMaxBytes)
		case o.At.IsZero() || o.PID < 0:
			return nil, status.Errorf(codes.InvalidArgument, "open %d needs its time and a non-negative pid", i)
		case len(o.Process) > transport.DecoyProcessMaxBytes || !printableDecoyText(o.Process):
			return nil, status.Errorf(codes.InvalidArgument, "open %d: the process name must be printable and at most %d bytes", i, transport.DecoyProcessMaxBytes)
		case o.Mechanism != "" && o.Mechanism != "fanotify" && o.Mechanism != "inotify":
			return nil, status.Errorf(codes.InvalidArgument, "open %d: the mechanism is fanotify or inotify", i)
		}
	}
	out := &transport.DecoyReportResponse{TenantID: info.TenantID}
	host := info.CommonName
	for i, d := range req.Decoys {
		_, registered, err := a.orch.RegisterDecoyFile(ctx, info.TenantID, host, d.Path, fingerprints[i])
		if err != nil {
			a.logDecoyFailure(info.TenantID, err)
			return nil, status.Error(codes.Unavailable, "the decoy could not be registered; retry later")
		}
		if registered {
			out.Registered++
		} else {
			out.Known++
		}
	}
	for _, o := range req.Opens {
		ids, err := a.store.LiveDecoyFileIDs(ctx, info.TenantID, host, o.Path)
		if err != nil {
			a.logDecoyFailure(info.TenantID, err)
			return nil, status.Error(codes.Unavailable, "the decoy registry is unavailable; retry later")
		}
		if len(ids) == 0 {
			out.Rejected++
			continue
		}
		if err := a.orch.RecordDecoyFileOpened(ctx, info.TenantID, ids[0], decoyFileReader(o, host), decoyOpenMethod(o), o.Path); err != nil {
			a.logDecoyFailure(info.TenantID, err)
			return nil, status.Error(codes.Unavailable, "the open could not be recorded; retry later")
		}
		out.Recorded++
	}
	return out, nil
}

func (a *agentService) logDecoyFailure(tenantID string, err error) {
	if a.logger != nil {
		a.logger.Warn("decoy report failed", "tenant_id", tenantID, "error", err)
	}
}

// validDecoyPath accepts an absolute, clean slash path of at most
// transport.DecoyPathMaxBytes printable characters.
func validDecoyPath(p string) bool {
	return len(p) >= 2 && len(p) <= transport.DecoyPathMaxBytes && strings.HasPrefix(p, "/") &&
		path.Clean(p) == p && printableDecoyText(p)
}

func printableDecoyText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// decoyFileReader names the program that opened a decoy file, with its host:
// the reader each alert is counted against. A watcher that could not see the
// opener reports none, and every such open on the host is one reader.
func decoyFileReader(o transport.DecoyOpen, host string) string {
	process := strings.TrimSpace(o.Process)
	if process == "" {
		process = "an unnamed process"
	}
	return process + " on " + host
}

// decoyOpenMethod records how the open was seen: its pid when known and the
// watcher's mechanism.
func decoyOpenMethod(o transport.DecoyOpen) string {
	method := "open"
	if o.PID > 0 {
		method += ", pid " + strconv.Itoa(o.PID)
	}
	if o.Mechanism != "" {
		method += ", seen by " + o.Mechanism
	}
	return method
}
