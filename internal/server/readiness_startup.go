// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
)

// A149: readiness that proves what a restart can leave unservable.
//
// /healthz answers as soon as the process serves HTTP, and the other /readyz
// checks prove the datastore, the event log, the projection tail and the
// signer. None of them proved that the SSH revocation list can be served
// current, or that audit history can be read: a replica restarted behind the
// revocation stream, or while a restored event history was still pending
// cutover, reported ready while its KRL answered 503 and its audit reads were
// refused. These two checks make readiness say so, so a load balancer keeps
// traffic off the replica until both can be served.

// probeSSHKRL brings the served SSH revocation list up to the event log, the
// same step a KRL request takes, and fails while it cannot: behind by more
// than one request's replay page, or on a revocation generation this issuer
// has not reconciled. A deployment without the SSH CA has nothing to prove.
func (s *Server) probeSSHKRL(ctx context.Context) error {
	sp := s.protocols
	if sp == nil || sp.ssh == nil {
		return nil
	}
	if err := sp.ssh.syncRevocations(ctx, false); err != nil {
		return errors.New("the SSH revocation list cannot be brought up to date with the event log yet")
	}
	return nil
}

// probeAuditRead takes the same history read an audit query or export takes
// and reads the log head inside it, failing while history reads are refused —
// for example while a restored history awaits cutover.
func (s *Server) probeAuditRead(ctx context.Context) error {
	if s.log == nil || s.audit == nil {
		return nil
	}
	if err := s.log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		_, err := s.log.LastSequence(readCtx)
		return err
	}); err != nil {
		return errors.New("audit history cannot be read yet")
	}
	return nil
}
