package store

import (
	"context"
	"fmt"
)

// FederationCheckpoint reads the source-cluster sequence watermark for peerID.
// It is a system, RLS-bypassing read because the cursor is over the peer's global
// JetStream sequence, not tenant data.
func (s *Store) FederationCheckpoint(ctx context.Context, peerID string) (uint64, error) {
	if peerID == "" {
		return 0, fmt.Errorf("store: federation peer id is required")
	}
	var seq int64
	err := s.pool.QueryRow(ctx,
		//trstctl:system-query — cross-tenant by design: federation peer checkpoints are deployment-wide system watermarks over a peer's global event sequence, while imported events still carry tenant_id and project under RLS.
		`SELECT source_seq FROM federation_peer_checkpoints WHERE peer_id = $1`, peerID).Scan(&seq)
	if err != nil {
		return 0, fmt.Errorf("store: read federation checkpoint for peer %q: %w", peerID, err)
	}
	if seq < 0 {
		seq = 0
	}
	return uint64(seq), nil
}

// EnsureFederationCheckpoint creates the peer cursor row at zero if it does not
// already exist. Keeping the create separate from reads makes missing migrations
// and invalid peer ids fail visibly.
func (s *Store) EnsureFederationCheckpoint(ctx context.Context, peerID string) error {
	if peerID == "" {
		return fmt.Errorf("store: federation peer id is required")
	}
	_, err := s.pool.Exec(ctx,
		//trstctl:system-query — cross-tenant by design: this initializes only the system cursor row for a peer event stream, not tenant read state; event payloads remain tenant-scoped.
		`INSERT INTO federation_peer_checkpoints (peer_id, source_seq)
		 VALUES ($1, 0)
		 ON CONFLICT (peer_id) DO NOTHING`, peerID)
	if err != nil {
		return fmt.Errorf("store: ensure federation checkpoint for peer %q: %w", peerID, err)
	}
	return nil
}

// AdvanceFederationCheckpoint moves peerID's imported source-sequence watermark
// forward after the event has been appended to the local log and projected.
func (s *Store) AdvanceFederationCheckpoint(ctx context.Context, peerID string, seq uint64) error {
	if peerID == "" {
		return fmt.Errorf("store: federation peer id is required")
	}
	_, err := s.pool.Exec(ctx,
		//trstctl:system-query — cross-tenant by design: this advances a deployment-wide federation import watermark; tenant isolation is enforced when the imported event is projected.
		`UPDATE federation_peer_checkpoints
		    SET source_seq = GREATEST(source_seq, $2), updated_at = now()
		  WHERE peer_id = $1`, peerID, int64(seq))
	if err != nil {
		return fmt.Errorf("store: advance federation checkpoint for peer %q: %w", peerID, err)
	}
	return nil
}
