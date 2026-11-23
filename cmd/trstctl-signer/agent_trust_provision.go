// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"trstctl.com/trstctl/internal/agentid/delegation"
	"trstctl.com/trstctl/internal/crypto"
)

// agentTrustBinding is public, operator-reviewed material. The signer process
// never accepts a new binding over its RPC transport; this one-shot command
// must run with access to the signer's local trust floor.
type agentTrustBinding struct {
	Kind         string `json:"kind"`
	TenantID     string `json:"tenant_id,omitempty"`
	KeyID        string `json:"key_id"`
	PublicKeyPEM string `json:"public_key_pem"`
	AuthRef      string `json:"auth_ref,omitempty"`
	Method       string `json:"method,omitempty"`
}

func runAgentTrustProvision(path, floorDir string) error {
	if path == "" || floorDir == "" {
		return errors.New("AGID trust provisioning requires an input JSON and signer --keystore")
	}
	f, err := os.Open(path) // #nosec G304 -- explicit operator-selected public input
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return errors.New("AGID trust binding must be a regular JSON file at most 1 MiB")
	}
	dec := json.NewDecoder(io.LimitReader(f, 1<<20))
	dec.DisallowUnknownFields()
	var binding agentTrustBinding
	if err := dec.Decode(&binding); err != nil {
		return fmt.Errorf("decode AGID trust binding: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("AGID trust binding has trailing data or exceeds 1 MiB")
	}
	for _, value := range []string{binding.KeyID, binding.TenantID, binding.AuthRef, binding.Method} {
		if value != strings.TrimSpace(value) {
			return errors.New("AGID trust binding contains a non-canonical identifier")
		}
	}
	if binding.KeyID == "" {
		return errors.New("AGID trust binding requires key_id")
	}
	public, err := crypto.ParsePublicKeyPEM([]byte(binding.PublicKeyPEM))
	if err != nil {
		return fmt.Errorf("AGID trust binding public key: %w", err)
	}
	ctx := context.Background()
	switch binding.Kind {
	case "root_anchor":
		if binding.TenantID == "" || binding.AuthRef == "" || binding.Method != "" {
			return errors.New("root anchor needs tenant_id and auth_ref, and no method")
		}
		store := delegation.NewDurableAnchorStore(floorDir)
		if err := store.ProvisionAgentRootAnchor(ctx, binding.TenantID, binding.KeyID, public.DER, binding.AuthRef); err != nil {
			return err
		}
		readDER, readAuthRef, err := store.ReadAgentRootAnchor(ctx, binding.TenantID, binding.KeyID)
		if err != nil || !bytes.Equal(readDER, public.DER) || readAuthRef != binding.AuthRef {
			return errors.New("AGID root-anchor local readback differs")
		}
	case "attestor":
		if binding.TenantID == "" || binding.Method == "" || binding.AuthRef != "" {
			return errors.New("attestor needs tenant_id and method, and no auth_ref")
		}
		store := delegation.NewDurableAttestationTrustStore(floorDir)
		if err := store.ProvisionAgentAttestor(ctx, binding.TenantID, binding.KeyID, public.DER, binding.Method); err != nil {
			return err
		}
		readDER, readMethod, err := store.ReadAgentAttestor(ctx, binding.TenantID, binding.KeyID)
		if err != nil || !bytes.Equal(readDER, public.DER) || readMethod != binding.Method {
			return errors.New("AGID attestor local readback differs")
		}
	case "reachability_key":
		if binding.TenantID != "" || binding.AuthRef != "" || binding.Method != "" {
			return errors.New("reachability key needs only key_id and public_key_pem")
		}
		store := delegation.NewDurableReachabilityTrustStore(floorDir)
		if err := store.PutVerdictSigner(ctx, binding.KeyID, public.DER); err != nil {
			return err
		}
		readDER, err := store.ReadVerdictSigner(ctx, binding.KeyID)
		if err != nil || !bytes.Equal(readDER, public.DER) {
			return errors.New("AGID reachability-key local readback differs")
		}
	default:
		return errors.New("AGID trust binding kind must be root_anchor, attestor, or reachability_key")
	}
	return nil
}
