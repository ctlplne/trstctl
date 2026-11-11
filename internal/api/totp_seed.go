// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/dynsecret"
)

// totpSeedProvider is a TOTP provider that says where its seed lives and how
// its codes are made (A239-L5).
type totpSeedProvider interface {
	Name() string
	DynamicSecretTOTPSeed() (ref string, digits int, period time.Duration, algorithm string, ok bool)
}

// totpSeedReplaceRequest is a replacement seed, as the identity provider's
// enrollment shows it (base32), and a code an authenticator made from it now.
type totpSeedReplaceRequest struct {
	Seed secretJSONBytes `json:"seed"`
	Code secretJSONBytes `json:"code"`
}

// replaceTOTPProviderSeed serves POST
// /api/v1/secrets/leases/providers/{provider}/totp-seed (A239-L5). When an
// account's MFA is enrolled again, its identity provider shows a new seed. The
// operator brings that seed and a code an authenticator made from it. The
// code proves the seed is the one enrolled and that the clocks agree; only
// then is the seed written, as the next version of the provider's secret://
// seed reference, through the secret store's own write path (the caller's
// write access to that name, restricted environments included). The next
// lease's code comes from it. A seed kept in a file: reference is replaced in
// the file: 409.
func (a *API) replaceTOTPProviderSeed(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	providerID := r.PathValue("provider")
	var provider totpSeedProvider
	for _, candidate := range a.secrets.dynamicProviders(tenantID) {
		if typed, ok := candidate.(totpSeedProvider); ok && candidate.Name() == providerID {
			if _, _, _, _, isTOTP := typed.DynamicSecretTOTPSeed(); isTOTP {
				provider = typed
			}
		}
	}
	if provider == nil {
		a.writeError(w, errStatus(http.StatusNotFound, "no TOTP provider "+providerID+" is configured"))
		return
	}
	ref, digits, period, algorithm, _ := provider.DynamicSecretTOTPSeed()
	name, isSecret := strings.CutPrefix(ref, "secret://")
	name = strings.Trim(name, "/")
	if !isSecret || name == "" {
		a.writeError(w, errStatus(http.StatusConflict, "the provider's seed_ref is not a secret:// reference; replace the seed where it is kept"))
		return
	}
	var req totpSeedReplaceRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	defer req.Seed.wipe()
	defer req.Code.wipe()
	if len(req.Seed) == 0 || len(req.Code) == 0 {
		a.writeError(w, errStatus(http.StatusBadRequest, "seed and code are required"))
		return
	}
	backend, err := dynsecret.NewTOTPBackend(dynsecret.TOTPConfig{SeedBase32: req.Seed, Digits: digits, Period: period, Algorithm: algorithm})
	if err != nil {
		a.writeError(w, errStatus(http.StatusUnprocessableEntity, "the seed is not a base32 TOTP seed of at least 80 bits"))
		return
	}
	match, err := backend.VerifyCode(req.Code)
	backend.Close()
	if err != nil {
		a.writeError(w, err)
		return
	}
	if !match {
		a.writeError(w, errStatus(http.StatusUnprocessableEntity, "the code is not the new seed's current code; check the seed and the authenticator's clock"))
		return
	}
	a.rotateApplicationSecret(w, r, name, idempotencyKey, secretWriteRequest{Name: name, Value: req.Seed})
}
