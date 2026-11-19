// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/kubetrust"
	"trstctl.com/trstctl/internal/store"
)

// A138: a TrustBundle rolled out from the control plane to several clusters,
// canary first. Each cluster is verified by its own controller's posture
// report (see applyKubernetesPostureTx), so the rollout state is a function of
// the event log.
const (
	EventKubernetesTrustRolloutStarted = "kubernetes.trust_rollout.started"
	EventKubernetesTrustRolloutPaused  = "kubernetes.trust_rollout.paused"
	EventKubernetesTrustRolloutResumed = "kubernetes.trust_rollout.resumed"

	KubernetesTrustRolloutStartedSchemaVersion = 2

	maxKubernetesTrustRolloutClusters   = 100
	maxKubernetesTrustRolloutNamespaces = 100
	maxKubernetesTrustBundleBytes       = 1 << 20
)

// KubernetesTrustRolloutStarted rolls one TrustBundle out to Clusters in order;
// the first is the canary. CABundlePEM is public CA certificates only, in the
// canonical form the cluster controller hashes for v2. Historical v1 events
// preserve the original trimmed bytes and their original SHA-256.
type KubernetesTrustRolloutStarted struct {
	RolloutID     string   `json:"rollout_id"`
	Name          string   `json:"name"`
	CABundlePEM   string   `json:"ca_bundle_pem"`
	BundleSHA256  string   `json:"bundle_sha256"`
	ConfigMapName string   `json:"config_map_name"`
	Key           string   `json:"key"`
	Namespaces    []string `json:"namespaces"`
	Clusters      []string `json:"clusters"`
}

// KubernetesTrustRolloutControlled pauses or resumes one rollout.
type KubernetesTrustRolloutControlled struct {
	RolloutID string `json:"rollout_id"`
}

var (
	kubernetesObjectNameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
	kubernetesNamespaceRE  = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	kubernetesConfigKeyRE  = regexp.MustCompile(`^[-._a-zA-Z0-9]{1,253}$`)
	kubernetesClusterIDRE  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// NormalizeKubernetesTrustBundlePEM encodes exactly the public certificate
// envelope new rollouts and the current cluster agent admit.
func NormalizeKubernetesTrustBundlePEM(bundle string) (string, string, error) {
	return kubetrust.NormalizeBundle(bundle)
}

// normalizeLegacyKubernetesTrustBundlePEM is the original v1 projection
// contract. Its bytes and validation must stay stable during retained replay.
func normalizeLegacyKubernetesTrustBundlePEM(bundle string) (string, string, error) {
	normalized := strings.TrimSpace(bundle) + "\n"
	if len(normalized) > maxKubernetesTrustBundleBytes {
		return "", "", errors.New("the CA bundle exceeds 1 MiB")
	}
	rest := []byte(normalized)
	certificates := 0
	for {
		rest = bytes.TrimSpace(rest)
		if len(rest) == 0 {
			break
		}
		block, next := pem.Decode(rest)
		if block == nil {
			return "", "", errors.New("the CA bundle must contain only PEM CERTIFICATE blocks")
		}
		if block.Type != "CERTIFICATE" {
			return "", "", fmt.Errorf("the CA bundle contains a %s block; only CERTIFICATE blocks are allowed", block.Type)
		}
		if _, err := certinfo.Inspect(pem.EncodeToMemory(block)); err != nil {
			return "", "", fmt.Errorf("the CA bundle holds a certificate that does not parse: %w", err)
		}
		certificates++
		rest = next
	}
	if certificates == 0 {
		return "", "", errors.New("the CA bundle must contain at least one CERTIFICATE block")
	}
	return normalized, crypto.SHA256Hex([]byte(normalized)), nil
}

// ValidateKubernetesTrustRolloutStarted checks the current v2 contract.
func ValidateKubernetesTrustRolloutStarted(p KubernetesTrustRolloutStarted) error {
	if !kubetrust.ValidRolloutID(p.RolloutID) {
		return errors.New("rollout_id must be a canonical nonzero UUID")
	}
	if err := kubetrust.ValidateTargets(p.Name, p.ConfigMapName, p.Key, p.Namespaces); err != nil {
		return err
	}
	canonical, hash, err := NormalizeKubernetesTrustBundlePEM(p.CABundlePEM)
	if err != nil {
		return err
	}
	if canonical != p.CABundlePEM || hash != p.BundleSHA256 {
		return errors.New("bundle_sha256 must match the canonical public CA bundle bytes")
	}
	return validateKubernetesTrustRolloutClusters(p.Clusters)
}

func validateLegacyKubernetesTrustRolloutStarted(p KubernetesTrustRolloutStarted) error {
	if _, err := uuid.Parse(p.RolloutID); err != nil {
		return errors.New("rollout_id must be a UUID")
	}
	if !kubernetesObjectNameRE.MatchString(p.Name) {
		return errors.New("name must be a Kubernetes object name (lowercase letters, digits, '-' and '.')")
	}
	if !kubernetesObjectNameRE.MatchString(p.ConfigMapName) {
		return errors.New("config_map_name must be a Kubernetes object name")
	}
	if !kubernetesConfigKeyRE.MatchString(p.Key) {
		return errors.New("key must be a ConfigMap key (letters, digits, '-', '_' and '.')")
	}
	normalized, hash, err := normalizeLegacyKubernetesTrustBundlePEM(p.CABundlePEM)
	if err != nil {
		return err
	}
	if normalized != p.CABundlePEM || hash != p.BundleSHA256 {
		return errors.New("bundle_sha256 must be the SHA-256 of the normalized CA bundle")
	}
	if len(p.Namespaces) == 0 || len(p.Namespaces) > maxKubernetesTrustRolloutNamespaces {
		return fmt.Errorf("namespaces must name 1 to %d namespaces", maxKubernetesTrustRolloutNamespaces)
	}
	seen := map[string]bool{}
	for _, namespace := range p.Namespaces {
		if !kubernetesNamespaceRE.MatchString(namespace) || seen[namespace] {
			return fmt.Errorf("namespace %q is not a distinct Kubernetes namespace name", namespace)
		}
		seen[namespace] = true
	}
	return validateKubernetesTrustRolloutClusters(p.Clusters)
}

func validateKubernetesTrustRolloutClusters(clusters []string) error {
	if len(clusters) == 0 || len(clusters) > maxKubernetesTrustRolloutClusters {
		return fmt.Errorf("clusters must name 1 to %d clusters", maxKubernetesTrustRolloutClusters)
	}
	seen := map[string]bool{}
	for _, cluster := range clusters {
		if !kubernetesClusterIDRE.MatchString(cluster) || seen[cluster] {
			return fmt.Errorf("cluster %q is not a distinct reported cluster id", cluster)
		}
		seen[cluster] = true
	}
	return nil
}

func decodeKubernetesTrustRolloutEvent(e events.Event, into any) error {
	decoder := json.NewDecoder(bytes.NewReader(e.Data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return fmt.Errorf("projections: decode %s: %w", e.Type, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("projections: decode %s: trailing data", e.Type)
	}
	if e.Time.IsZero() || e.Sequence == 0 {
		return fmt.Errorf("projections: %s requires event time and a positive stream sequence", e.Type)
	}
	return nil
}

func (p *Projector) applyKubernetesTrustRolloutTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventKubernetesTrustRolloutStarted:
		var pl KubernetesTrustRolloutStarted
		if err := decodeKubernetesTrustRolloutEvent(e, &pl); err != nil {
			return true, err
		}
		validate := ValidateKubernetesTrustRolloutStarted
		if schemaVersionOf(e) == 1 {
			validate = validateLegacyKubernetesTrustRolloutStarted
		}
		if err := validate(pl); err != nil {
			return true, fmt.Errorf("projections: %s: %w", e.Type, err)
		}
		clusters := make([]store.KubernetesTrustRolloutCluster, 0, len(pl.Clusters))
		for _, cluster := range pl.Clusters {
			clusters = append(clusters, store.KubernetesTrustRolloutCluster{ClusterID: cluster})
		}
		return true, p.store.ApplyKubernetesTrustRolloutStartedTx(ctx, tx, store.KubernetesTrustRollout{
			TenantID: e.TenantID, ID: pl.RolloutID, Name: pl.Name, CABundlePEM: pl.CABundlePEM,
			BundleSHA256: pl.BundleSHA256, ConfigMapName: pl.ConfigMapName, BundleKey: pl.Key,
			Namespaces: pl.Namespaces, Clusters: clusters,
		}, e.Time, e.Sequence)
	case EventKubernetesTrustRolloutPaused, EventKubernetesTrustRolloutResumed:
		var pl KubernetesTrustRolloutControlled
		if err := decodeKubernetesTrustRolloutEvent(e, &pl); err != nil {
			return true, err
		}
		if _, err := uuid.Parse(pl.RolloutID); err != nil {
			return true, fmt.Errorf("projections: %s: rollout_id must be a UUID", e.Type)
		}
		state := store.KubernetesTrustRolloutPaused
		if e.Type == EventKubernetesTrustRolloutResumed {
			state = store.KubernetesTrustRolloutRunning
		}
		return true, p.store.ApplyKubernetesTrustRolloutStateTx(ctx, tx, e.TenantID, pl.RolloutID, state, e.Time, e.Sequence)
	}
	return false, nil
}
