// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// AgentCertificateBinding is a read projection of a CA-issued enrollment or
// authenticated renewal. It contains public certificate metadata only.
type AgentCertificateBinding struct {
	TenantID, AgentID, Serial, Fingerprint string
	NotAfter                               time.Time
	EventSeq                               uint64
}

var ErrAgentNameAlreadyEnrolled = errors.New("agent name already has a live enrollment")

func (s *Store) AgentNameAvailableForEnrollment(ctx context.Context, tenantID, agentID string) (bool, error) {
	var occupied bool
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (
            SELECT 1 FROM agent_certificate_bindings
             WHERE tenant_id=$1 AND agent_id=$2 AND not_after > now()
        ) OR EXISTS (
            SELECT 1 FROM agents
			 WHERE tenant_id=$1 AND id=$2
        )`, tenantID, agentID).Scan(&occupied)
	})
	return !occupied, err
}

// AgentCertificateMatches checks the exact CA-issued certificate for names
// enrolled since this projection was introduced. A missing binding requires
// source-event proof before a legacy certificate can use the agent channel.
func (s *Store) AgentCertificateMatches(ctx context.Context, tenantID, agentID, serial, fingerprint string) (bound, matches bool, err error) {
	err = s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (
            SELECT 1 FROM agent_certificate_bindings WHERE tenant_id=$1 AND agent_id=$2
        ), EXISTS (
            SELECT 1 FROM agent_certificate_bindings
             WHERE tenant_id=$1 AND agent_id=$2 AND serial=$3 AND fingerprint=$4 AND not_after > now()
        )`, tenantID, agentID, strings.ToLower(serial), strings.ToLower(fingerprint)).Scan(&bound, &matches)
	})
	return
}

func (s *Store) ApplyAgentCertificateBindingTx(ctx context.Context, tx pgx.Tx, binding AgentCertificateBinding) error {
	if binding.TenantID == "" || binding.AgentID == "" || binding.Serial == "" || binding.Fingerprint == "" || binding.NotAfter.IsZero() || binding.EventSeq == 0 {
		return errors.New("store: incomplete agent certificate binding event")
	}
	_, err := tx.Exec(ctx, `INSERT INTO agent_certificate_bindings
        (tenant_id, agent_id, serial, fingerprint, not_after, event_seq)
        VALUES ($1,$2,$3,$4,$5,$6)
        ON CONFLICT (tenant_id, agent_id, serial) DO NOTHING`,
		binding.TenantID, binding.AgentID, strings.ToLower(binding.Serial), strings.ToLower(binding.Fingerprint), binding.NotAfter, binding.EventSeq)
	return err
}
