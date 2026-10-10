// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/editionseam"
	"trstctl.com/trstctl/internal/events"
	coreorch "trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/signing"
	corestore "trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/succession"
	pcasstore "trstctl.com/trstctl/internal/succession/store"
)

const GenesisDestination = "pcas.genesis-request"

type genesisPayload struct {
	RequestID string        `json:"request_id"`
	QueuedAt  time.Time     `json:"queued_at"`
	Actor     *events.Actor `json:"actor,omitempty"`
	Request   struct {
		IdentityID      string `json:"identity_id"`
		Algorithm       string `json:"algorithm"`
		DeploymentScope string `json:"deployment_scope"`
	} `json:"request"`
}

// GenesisWorker creates a tenant-bound key and an independently verifiable
// signed anchor. All signer calls occur from the durable outbox consumer, never
// from the HTTP handler. Replayed commands reuse the exact sealed handles and
// the signer's operation-journaled signature.
type GenesisWorker struct {
	repo    *pcasstore.Repo
	log     *events.Log
	custody editionseam.KEMCustody
}

func NewGenesisWorker(store *corestore.Store, log *events.Log, custody editionseam.KEMCustody) *GenesisWorker {
	return &GenesisWorker{repo: pcasstore.New(store), log: log, custody: custody}
}

func (w *GenesisWorker) Deliver(ctx context.Context, m coreorch.Message) error {
	if m.Destination != GenesisDestination {
		return fmt.Errorf("pcas genesis: unexpected destination %q", m.Destination)
	}
	if w.log == nil || w.custody == nil {
		return errors.New("pcas genesis: event log and isolated signer custody are required")
	}
	var p genesisPayload
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return fmt.Errorf("pcas genesis: decode request: %w", err)
	}
	if p.RequestID == "" || p.QueuedAt.IsZero() || p.Request.IdentityID == "" || p.Request.DeploymentScope == "" || p.Request.Algorithm == "" {
		return errors.New("pcas genesis: request id, queued time, identity, deployment scope and algorithm are required")
	}
	algorithm := crypto.Algorithm(p.Request.Algorithm)
	anchor, found, err := w.repo.GetGenesis(ctx, m.TenantID, p.Request.IdentityID)
	if err != nil {
		return err
	}
	if found {
		if anchor.Genesis.Algorithm != algorithm || anchor.Genesis.DeploymentScope != p.Request.DeploymentScope {
			return errors.New("pcas genesis: identity already has a different immutable anchor")
		}
		return succession.VerifyGenesis(anchor.TrustRootPublicDER, anchor.Genesis)
	}

	rootHandle := fmt.Sprintf("pcas:tenant-root:v1:%x", crypto.SHA256Sum([]byte("trstctl/pcas/root/v1:"+m.TenantID)))
	root, err := w.signerForOrGenerate(ctx, rootHandle, crypto.ECDSAP256)
	if err != nil {
		return fmt.Errorf("pcas genesis: tenant trust root: %w", err)
	}
	key, err := w.signerForOrGenerate(ctx, succession.TenantKeyHandle(m.TenantID, p.Request.IdentityID, 0), algorithm)
	if err != nil {
		return fmt.Errorf("pcas genesis: identity key: %w", err)
	}
	genesis := succession.GenesisRecord{
		DeploymentScope: p.Request.DeploymentScope, IdentityID: p.Request.IdentityID,
		TenantID: m.TenantID, Algorithm: algorithm, PublicKey: key.Public().DER, Epoch: 0,
	}
	genesisDigest, err := succession.GenesisDigest(genesis)
	if err != nil {
		return err
	}
	// VerifyGenesis checks a message signature over GenesisDigest, so hash that
	// digest once more before the remote digest-signing RPC. Operation journaling
	// makes ECDSA's randomized signature byte-identical after a worker crash.
	signDigest, err := crypto.Digest(crypto.SHA256, genesisDigest)
	if err != nil {
		return err
	}
	genesis.TrustRootAtt, err = root.SignDigestForOperation(
		"pcas-genesis-att:"+succession.TenantIdentityKey(m.TenantID, p.Request.IdentityID),
		signDigest, crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		return fmt.Errorf("pcas genesis: sign anchor: %w", err)
	}
	if err := succession.VerifyGenesis(root.Public().DER, genesis); err != nil {
		return fmt.Errorf("pcas genesis: verify anchor before publish: %w", err)
	}
	ev, err := succession.Encode(succession.GenesisV1{
		RequestID: p.RequestID, IdentityID: p.Request.IdentityID, TenantID: m.TenantID,
		DeploymentScope: p.Request.DeploymentScope, Algorithm: p.Request.Algorithm,
		PublicKeyDER: key.Public().DER, Epoch: 0, TrustRootAtt: genesis.TrustRootAtt,
		TrustRootPublicDER: root.Public().DER,
	})
	if err != nil {
		return err
	}
	ev.ID = "pcas-genesis-v1-" + succession.TenantIdentityKey(m.TenantID, p.Request.IdentityID)
	ev.Time = p.QueuedAt
	ev.Actor = p.Actor
	if _, err := w.log.Append(ctx, ev); err != nil {
		return fmt.Errorf("pcas genesis: append immutable event: %w", err)
	}
	return w.repo.PutGenesis(ctx, m.TenantID, pcasstore.GenesisAnchor{
		Genesis: genesis, TrustRootPublicDER: root.Public().DER, EventID: ev.ID, RequestID: p.RequestID,
	})
}

func (w *GenesisWorker) signerForOrGenerate(ctx context.Context, handle string, alg crypto.Algorithm) (*signing.RemoteSigner, error) {
	remote, err := w.custody.SignerForHandle(ctx, handle)
	if err != nil && status.Code(err) != codes.NotFound {
		return nil, err
	}
	if remote == nil {
		remote, err = w.custody.GenerateKeyHandle(ctx, alg, handle)
		if status.Code(err) == codes.AlreadyExists {
			remote, err = w.custody.SignerForHandle(ctx, handle)
		}
		if err != nil {
			return nil, err
		}
	}
	if remote.Algorithm() != alg {
		return nil, fmt.Errorf("existing signer handle has algorithm %s, requested %s", remote.Algorithm(), alg)
	}
	return remote, nil
}
