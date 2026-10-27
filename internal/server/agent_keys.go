// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
)

// agent_keys.go publishes each agent's current public keys for the customer's
// authorization server, so an agent can authenticate there with its trstctl
// identity (MCP authorization, private_key_jwt per RFC 7523). The authorization
// server is configured with this URL as the agent client's key set and checks the
// agent's signed client assertions against it; trstctl never becomes the
// authorization server and never sees an access token.
//
// The set holds the public keys of the agent's broker-issued certificates that are
// valid now, each under its SPKI SHA-256 as the key ID. Revoking a certificate
// (POST /api/v1/certificates/bulk-revoke) takes its key out of the set; the
// authorization server stops accepting it when its key cache next refreshes. Like
// the CRL and OCSP routes the path is public: the keys are public, and an unknown
// tenant or agent and an agent without a valid certificate get the same empty set.

// agentKeySetPrefix is the public namespace of the agent key sets.
const agentKeySetPrefix = "/agent-keys/"

func (s *Server) agentKeySetHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /agent-keys/{tenant}/{agent}/jwks.json", s.agentKeySet)
	mux.HandleFunc(agentKeySetPrefix, http.NotFound)
	return mux
}

func (s *Server) agentKeySet(w http.ResponseWriter, r *http.Request) {
	tenantID, agentID := r.PathValue("tenant"), r.PathValue("agent")
	set := crypto.JWKS{Keys: []crypto.JWK{}}
	if _, err := uuid.Parse(tenantID); err == nil && s.store != nil && validAgentKeySetID(agentID) {
		keys, err := s.store.ListValidBrokerAgentKeys(r.Context(), tenantID, agentID, time.Now().UTC())
		if err != nil {
			http.Error(w, "agent keys are unavailable", http.StatusServiceUnavailable)
			return
		}
		for _, key := range keys {
			spki, err := crypto.CertificateSubjectPublicKeyInfo(key.CertificateDER)
			if err != nil {
				continue
			}
			jwk, err := crypto.PublicJWK(crypto.PublicKey{DER: spki}, crypto.SHA256Hex(spki))
			if err != nil {
				continue
			}
			set.Keys = append(set.Keys, jwk)
		}
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(set)
}

// validAgentKeySetID accepts the agent IDs the broker issues for, without control
// characters or path separators, so a lookup never runs on arbitrary input.
func validAgentKeySetID(agentID string) bool {
	return agentID != "" && len(agentID) <= 256 && !strings.ContainsAny(agentID, "/\\\x00\r\n")
}
