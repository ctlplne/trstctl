// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// kubernetesDecoyNamespace keys a Kubernetes decoy's first id by tenant,
// cluster, namespace and service account, so registrations of one service
// account that arrive together make one decoy.
var kubernetesDecoyNamespace = uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl/kubernetes-decoy"))

// ErrKubernetesDecoyExists refuses a second live decoy for one service account.
var ErrKubernetesDecoyExists = errors.New("a live decoy already watches this service account")

// RegisterKubernetesDecoy records a Kubernetes service account token decoy
// (Q6-O2): a service account bound to nothing and its token Secret, in a
// namespace of a cluster whose API server sends its audit events to trstctl.
// trstctl holds no token: the operator applies the manifest the API returns.
// A service account has one live decoy; after it is retired, registering it
// again makes a new decoy.
func (o *Orchestrator) RegisterKubernetesDecoy(ctx context.Context, tenantID, name, placement, cluster, namespace, account, secretName string) (store.HoneyToken, error) {
	live, err := o.store.LiveKubernetesDecoys(ctx, tenantID, cluster)
	if err != nil {
		return store.HoneyToken{}, err
	}
	for _, d := range live {
		if d.K8sNamespace == namespace && d.K8sServiceAccount == account {
			return d, ErrKubernetesDecoyExists
		}
	}
	id := uuid.NewSHA1(kubernetesDecoyNamespace, []byte(tenantID+"\x00"+cluster+"\x00"+namespace+"\x00"+account)).String()
	if previous, err := o.store.GetHoneyToken(ctx, tenantID, id); err == nil && previous.State == "revoked" {
		id = uuid.NewString()
	} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return store.HoneyToken{}, err
	}
	payload, err := json.Marshal(projections.HoneyTokenCreated{
		ID: id, Name: name, Placement: placement, TokenHash: "kubernetes-decoy:" + id,
		K8sCluster: cluster, K8sNamespace: namespace, K8sServiceAccount: account, K8sSecret: secretName,
	})
	if err != nil {
		return store.HoneyToken{}, err
	}
	if _, err := o.emit(ctx, projections.EventHoneyTokenCreated, tenantID, payload); err != nil {
		return store.HoneyToken{}, err
	}
	return o.store.GetHoneyToken(ctx, tenantID, id)
}

// RecordKubernetesDecoyEvent records one audit event that read a Kubernetes
// decoy's token Secret or used its token, naming the reader; the projection
// alerts once per distinct reader, as for a decoy secret's readers.
func (o *Orchestrator) RecordKubernetesDecoyEvent(ctx context.Context, tenantID, id, reader, method, requestURI string) error {
	return o.RecordDecoySecretRead(ctx, tenantID, id, reader, method, requestURI)
}
