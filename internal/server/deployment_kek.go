// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
	transitpkg "trstctl.com/trstctl/internal/transit"
)

// A198: the deployment KEK (secrets.kek_file) as a keyring a served rotation
// moves to a key under an operator wrapper, and the leader worker that drives
// a recorded rotation.

const (
	// deploymentKEKStepInterval is how often the leader looks for a recorded
	// rotation to advance; a rotation request wakes it at once.
	deploymentKEKStepInterval = 5 * time.Second
	// deploymentKEKRetryInterval spaces retries after a step fails.
	deploymentKEKRetryInterval = 30 * time.Second
	// agidReachabilityKeyFile is the AGID verdict key sealed under the
	// deployment KEK inside the signer key store directory (its package keeps
	// the same relative path; a test pins the two together).
	agidReachabilityKeyFile = "agid-control-plane/reachability-verdict-v1.sealed"
)

// runDeploymentKEK is the deployment KEK every control-plane path uses and its
// served rotation (nil without a database or event log).
type runDeploymentKEK struct {
	keyring  sealKeyWrapper
	rotation *tenantseal.DeploymentRotation
}

// deploymentKeyringFromFile wraps the deployment key file in the deployment
// KEK keyring over the shared wrapper registry. Anything that is not the key
// file (a keyring already, a test double) passes through.
func deploymentKeyringFromFile(deployment sealKeyWrapper, st *store.Store, registry tenantseal.DomainKEKManager) (sealKeyWrapper, error) {
	local, ok := deployment.(*seal.LocalKEK)
	if !ok || st == nil {
		return deployment, nil
	}
	return tenantseal.NewDeploymentKeyring(local, st, registry)
}

// deploymentSealedFiles names the deployment-scoped files sealed under the
// deployment KEK, which a rotation re-wraps in place: the SAML encryption
// identity, the SCEP/CMP RA identity, a transit keyring checkpoint, and the
// AGID reachability verdict key.
func deploymentSealedFiles(cfg *config.Config) []string {
	var files []string
	if cfg.Auth.SAML.Enabled && strings.TrimSpace(cfg.Auth.SAML.SPKeyFile) != "" {
		files = append(files, cfg.Auth.SAML.SPKeyFile)
	}
	if strings.TrimSpace(cfg.Protocols.RAKeyFile) != "" {
		files = append(files, cfg.Protocols.RAKeyFile)
	}
	if strings.TrimSpace(cfg.Transit.KeyringDir) != "" {
		files = append(files, transitpkg.CheckpointPath(cfg.Transit.KeyringDir))
	}
	if strings.TrimSpace(cfg.Signer.KeyStoreDir) != "" {
		files = append(files, filepath.Join(cfg.Signer.KeyStoreDir, agidReachabilityKeyFile))
	}
	return files
}

// deploymentKEKAPI is the API's view of the deployment KEK.
func (s *Server) deploymentKEKAPI(d Deps) api.DeploymentKEKService {
	service := api.DeploymentKEKService{OperatorTenantID: d.DeploymentKEKOperatorTenantID, Wake: s.wakeDeploymentKEK}
	if s.deploymentKEK != nil {
		service.Lifecycle = s.deploymentKEK
	}
	return service
}

func (s *Server) deploymentKEKWakeup() chan struct{} {
	s.deploymentKEKWakeOnce.Do(func() { s.deploymentKEKWake = make(chan struct{}, 1) })
	return s.deploymentKEKWake
}

// wakeDeploymentKEK asks the worker to step now rather than at its next tick.
func (s *Server) wakeDeploymentKEK() {
	select {
	case s.deploymentKEKWakeup() <- struct{}{}:
	default:
	}
}

// RunDeploymentKEKRotation drives a recorded deployment KEK rotation on the
// leader. Each step is a bounded unit of re-wrapping, so a rotation advances
// while requests keep being served, and a new leader resumes it from the
// recorded step.
func (s *Server) RunDeploymentKEKRotation(ctx context.Context) {
	if s.deploymentKEK == nil {
		return
	}
	wake := s.deploymentKEKWakeup()
	for {
		wait := deploymentKEKStepInterval
		for ctx.Err() == nil {
			done, err := s.deploymentKEK.Step(ctx)
			if err != nil {
				if s.logger != nil {
					s.logger.Warn("deployment KEK rotation step did not finish; retrying", slog.String("error", err.Error()))
				}
				wait = deploymentKEKRetryInterval
				break
			}
			if done {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
		case <-time.After(wait):
		}
	}
}
