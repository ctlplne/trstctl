// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"encoding/json"
	"net/http"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/store"
)

// Algorithm choice is reviewed input, not a hint to a CA. A host retains the
// ML-DSA private key across CSR signing and installation. Receiver compatibility
// still requires the host's configured native readback and independent clients.
func validateEndpointSubjectChoice(algorithm string, target endpointBindingTargetSummary) error {
	if err := store.ValidateEndpointSubjectAlgorithm(algorithm); err != nil {
		return errWithStatus(http.StatusBadRequest, err)
	}
	if algorithm == "" || algorithm == string(crypto.ECDSAP256) {
		return nil
	}
	if !relay.ExecutesOnHost(target.Connector) || !custody.TargetExecutorIsAgent(target.Config) {
		return errStatus(http.StatusUnprocessableEntity, "ML-DSA endpoint enrollment requires executor=agent so the serving host keeps the private key through issuance and installation; no key or certificate was generated")
	}
	return nil
}

// Omission retains an existing endpoint's durable algorithm intent, including
// when creating a replacement. It must not silently downgrade a PQC listener.
func endpointSubjectChoice(requested string, existing, replaced *identityResponse) (string, error) {
	if requested != "" {
		return requested, store.ValidateEndpointSubjectAlgorithm(requested)
	}
	source := existing
	if source == nil {
		source = replaced
	}
	if source == nil {
		return "", nil
	}
	var attributes map[string]json.RawMessage
	if len(source.Attributes) != 0 {
		if err := json.Unmarshal(source.Attributes, &attributes); err != nil {
			return "", errStatus(http.StatusConflict, "existing subject algorithm cannot be read; review the identity before enrollment")
		}
	}
	raw, present := attributes["subject_key_algorithm"]
	if !present {
		return "", nil
	}
	var algorithm string
	if err := json.Unmarshal(raw, &algorithm); err != nil || algorithm == "" {
		return "", errStatus(http.StatusConflict, "existing subject_key_algorithm must name a supported algorithm; review the identity before enrollment")
	}
	if err := store.ValidateEndpointSubjectAlgorithm(algorithm); err != nil {
		return "", errWithStatus(http.StatusConflict, err)
	}
	return algorithm, nil
}
