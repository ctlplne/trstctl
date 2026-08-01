// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/orchestrator"
)

const (
	defaultRekorEndpoint = "https://rekor.sigstore.dev/api/v1/log/entries"
	rekorMaxResponseBody = 1 << 20
)

type rekorHandler struct {
	endpoint     string
	client       *http.Client
	logPublicKey crypto.PublicKey
}

var _ orchestrator.Handler = (*rekorHandler)(nil)

func rekorHandlerFromConfig(cfg config.CodeSigningRekor, guard *egress.Guard) (orchestrator.Handler, error) {
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		endpoint = defaultRekorEndpoint
	}
	keyFile := strings.TrimSpace(cfg.LogPublicKeyFile)
	if keyFile == "" {
		return nil, fmt.Errorf("code-signing Rekor client: log_public_key_file is required")
	}
	keyPEM, err := os.ReadFile(keyFile) // #nosec G304 -- operator-configured local file path from deployment config (CWE-22)
	if err != nil {
		return nil, fmt.Errorf("code-signing Rekor client: read trusted log public key: %w", err)
	}
	logPublicKey, err := crypto.ParsePublicKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("code-signing Rekor client: parse trusted log public key: %w", err)
	}
	client, err := incidentNotificationHTTPClient(endpoint, cfg.TimeoutDuration, cfg.AllowPrivateCIDRs, cfg.AllowInsecureHTTP, guard)
	if err != nil {
		return nil, fmt.Errorf("code-signing Rekor client: %w", err)
	}
	return &rekorHandler{endpoint: endpoint, client: client, logPublicKey: logPublicKey}, nil
}

type rekorProposedEntry struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Spec       rekorHashedSpec `json:"spec"`
}

type rekorHashedSpec struct {
	Data      rekorData      `json:"data"`
	Signature rekorSignature `json:"signature"`
}

type rekorData struct {
	Hash rekorHash `json:"hash"`
}

type rekorHash struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

type rekorSignature struct {
	Content   []byte         `json:"content"`
	PublicKey rekorPublicKey `json:"publicKey"`
}

type rekorPublicKey struct {
	Content []byte `json:"content"`
}

type rekorLogEntry struct {
	Body           string            `json:"body"`
	IntegratedTime *int64            `json:"integratedTime"`
	LogID          string            `json:"logID"`
	LogIndex       *int64            `json:"logIndex"`
	Verification   rekorVerification `json:"verification"`
}

type rekorVerification struct {
	SignedEntryTimestamp []byte `json:"signedEntryTimestamp"`
}

func (h *rekorHandler) Deliver(ctx context.Context, message orchestrator.Message) error {
	if h == nil || h.client == nil || h.endpoint == "" || len(h.logPublicKey.DER) == 0 {
		return fmt.Errorf("rekor: handler is not configured")
	}
	if message.Destination != defaultRekorDestination {
		return fmt.Errorf("rekor: unsupported destination %q", message.Destination)
	}
	var payload codeSigningTransparencyPayload
	if err := json.Unmarshal(message.Payload, &payload); err != nil {
		return fmt.Errorf("rekor: decode transparency payload: %w", err)
	}
	entry, digest, err := rekorEntryFromPayload(payload)
	if err != nil {
		return err
	}
	if err := crypto.VerifyDigest(
		crypto.PublicKey{Algorithm: crypto.Algorithm(payload.Algorithm), DER: payload.PublicKeyDER},
		digest, payload.Signature,
		crypto.SignOptions{Hash: crypto.SHA256, RSAPadding: crypto.RSAPKCS1v15},
	); err != nil {
		return fmt.Errorf("rekor: refuse invalid artifact signature: %w", err)
	}
	body, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("rekor: encode HashedRekord: %w", err)
	}
	defer secret.Wipe(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("rekor: build request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Trstctl-Idempotency-Key", message.IdempotencyKey)
	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("rekor: publish HashedRekord: request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	responseBody, err := secret.ReadBounded(resp.Body, rekorMaxResponseBody+1)
	if err != nil {
		return fmt.Errorf("rekor: read response: %w", err)
	}
	defer secret.Wipe(responseBody)
	if len(responseBody) > rekorMaxResponseBody {
		return fmt.Errorf("rekor: response exceeds %d bytes", rekorMaxResponseBody)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
		return fmt.Errorf("rekor: publish HashedRekord returned HTTP %d", resp.StatusCode)
	}
	receiptBody := responseBody
	var fetchedBody []byte
	if resp.StatusCode == http.StatusConflict {
		// Rekor v1 reports an already-integrated leaf as 409 plus a Location
		// header. Some compatible deployments return the existing entry map in
		// the 409 body, so accept that only when its pinned SET verifies; otherwise
		// retrieve the same-origin entry named by Location and verify it below.
		if err := validateRekorReceipt(receiptBody, entry, h.logPublicKey); err != nil {
			fetchedBody, err = h.fetchExistingReceipt(ctx, resp.Header.Get("Location"))
			if err != nil {
				return err
			}
			defer secret.Wipe(fetchedBody)
			receiptBody = fetchedBody
		}
	}
	if err := validateRekorReceipt(receiptBody, entry, h.logPublicKey); err != nil {
		return fmt.Errorf("rekor: invalid transparency receipt: %w", err)
	}
	return nil
}

func (h *rekorHandler) fetchExistingReceipt(ctx context.Context, rawLocation string) ([]byte, error) {
	base, err := url.Parse(h.endpoint)
	if err != nil {
		return nil, fmt.Errorf("rekor: configured endpoint is invalid")
	}
	location, err := url.Parse(strings.TrimSpace(rawLocation))
	if err != nil || strings.TrimSpace(rawLocation) == "" {
		return nil, fmt.Errorf("rekor: duplicate response omitted a valid entry Location")
	}
	resolved := base.ResolveReference(location)
	wantPrefix := strings.TrimSuffix(base.EscapedPath(), "/") + "/"
	entryID := strings.TrimPrefix(resolved.EscapedPath(), wantPrefix)
	if resolved.User != nil || resolved.Scheme != base.Scheme || !strings.EqualFold(resolved.Host, base.Host) || !strings.HasPrefix(resolved.EscapedPath(), wantPrefix) || strings.Contains(entryID, "/") || (len(entryID) != 64 && len(entryID) != 80) || resolved.RawQuery != "" || resolved.Fragment != "" {
		return nil, fmt.Errorf("rekor: duplicate entry Location is outside the configured log endpoint")
	}
	if _, err := hex.DecodeString(entryID); err != nil {
		return nil, fmt.Errorf("rekor: duplicate entry Location has a malformed entry id")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resolved.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("rekor: build duplicate-entry lookup")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rekor: retrieve existing entry: request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_ = secret.DrainBounded(resp.Body, 4096)
		return nil, fmt.Errorf("rekor: retrieve existing entry returned HTTP %d", resp.StatusCode)
	}
	body, err := secret.ReadBounded(resp.Body, rekorMaxResponseBody+1)
	if err != nil {
		return nil, fmt.Errorf("rekor: read existing entry: %w", err)
	}
	if len(body) > rekorMaxResponseBody {
		secret.Wipe(body)
		return nil, fmt.Errorf("rekor: existing entry response exceeds %d bytes", rekorMaxResponseBody)
	}
	return body, nil
}

func rekorEntryFromPayload(payload codeSigningTransparencyPayload) (rekorProposedEntry, []byte, error) {
	if len(payload.Signature) == 0 || len(payload.PublicKeyDER) == 0 {
		return rekorProposedEntry{}, nil, fmt.Errorf("rekor: signature and public key are required")
	}
	digestHex := strings.ToLower(strings.TrimSpace(payload.DigestHex))
	digest, err := hex.DecodeString(digestHex)
	if err != nil || len(digest) != 32 {
		return rekorProposedEntry{}, nil, fmt.Errorf("rekor: digest_hex must be one SHA-256 digest")
	}
	publicPEM := crypto.MarshalPublicKeyPEM(payload.PublicKeyDER)
	return rekorProposedEntry{
		APIVersion: "0.0.1",
		Kind:       "hashedrekord",
		Spec: rekorHashedSpec{
			Data: rekorData{Hash: rekorHash{Algorithm: "sha256", Value: digestHex}},
			Signature: rekorSignature{
				Content:   append([]byte(nil), payload.Signature...),
				PublicKey: rekorPublicKey{Content: publicPEM},
			},
		},
	}, digest, nil
}

func validateRekorReceipt(body []byte, proposed rekorProposedEntry, logPublicKey crypto.PublicKey) error {
	if len(logPublicKey.DER) == 0 || logPublicKey.Algorithm == "" {
		return fmt.Errorf("trusted Rekor log public key is absent")
	}
	var entries map[string]rekorLogEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return fmt.Errorf("decode entry map: %w", err)
	}
	if len(entries) != 1 {
		return fmt.Errorf("receipt contains %d entries, want exactly one", len(entries))
	}
	for uuid, logged := range entries {
		if strings.TrimSpace(uuid) == "" || logged.IntegratedTime == nil || *logged.IntegratedTime <= 0 || logged.LogIndex == nil || *logged.LogIndex < 0 || strings.TrimSpace(logged.LogID) == "" || len(logged.Verification.SignedEntryTimestamp) == 0 {
			return fmt.Errorf("receipt is missing UUID/log position/log identity/signed entry timestamp")
		}
		if got, want := strings.ToLower(strings.TrimSpace(logged.LogID)), crypto.SHA256Hex(logPublicKey.DER); got != want {
			return fmt.Errorf("receipt logID is not bound to the configured Rekor log public key")
		}
		decoded, err := base64.StdEncoding.DecodeString(logged.Body)
		if err != nil {
			return fmt.Errorf("decode logged body: %w", err)
		}
		var echoed rekorProposedEntry
		if err := json.Unmarshal(decoded, &echoed); err != nil {
			return fmt.Errorf("decode logged HashedRekord: %w", err)
		}
		if echoed.APIVersion != proposed.APIVersion || echoed.Kind != proposed.Kind || echoed.Spec.Data.Hash != proposed.Spec.Data.Hash || !bytes.Equal(echoed.Spec.Signature.Content, proposed.Spec.Signature.Content) || !bytes.Equal(echoed.Spec.Signature.PublicKey.Content, proposed.Spec.Signature.PublicKey.Content) {
			return fmt.Errorf("logged body does not bind the submitted digest, signature, and public key")
		}
		leafUUID := strings.ToLower(strings.TrimSpace(uuid))
		if len(leafUUID) == 80 {
			leafUUID = leafUUID[16:]
		}
		if len(leafUUID) != 64 {
			return fmt.Errorf("receipt UUID is not a Rekor leaf hash")
		}
		if _, err := hex.DecodeString(leafUUID); err != nil {
			return fmt.Errorf("receipt UUID is not hexadecimal: %w", err)
		}
		leafInput := make([]byte, 1, len(decoded)+1)
		leafInput[0] = 0 // RFC 6962 domain separator for a Merkle leaf.
		leafInput = append(leafInput, decoded...)
		if leafUUID != crypto.SHA256Hex(leafInput) {
			return fmt.Errorf("receipt UUID does not bind the logged body")
		}
		canonical, err := canonicalRekorSET(logged)
		if err != nil {
			return err
		}
		if err := verifyRekorSET(logPublicKey, canonical, logged.Verification.SignedEntryTimestamp); err != nil {
			return fmt.Errorf("signed entry timestamp is not valid under the configured Rekor log public key: %w", err)
		}
	}
	return nil
}

// canonicalRekorSET matches Rekor v1's RFC 8785/JCS bundle payload. These four
// fields are strings/integers, and declaring them in lexicographic key order
// makes encoding/json's compact output exactly the JCS representation:
// body, integratedTime, logID, logIndex.
func canonicalRekorSET(logged rekorLogEntry) ([]byte, error) {
	if logged.IntegratedTime == nil || logged.LogIndex == nil {
		return nil, fmt.Errorf("receipt cannot form signed entry timestamp payload without time/index")
	}
	return json.Marshal(struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogID          string `json:"logID"`
		LogIndex       int64  `json:"logIndex"`
	}{
		Body: logged.Body, IntegratedTime: *logged.IntegratedTime,
		LogID: logged.LogID, LogIndex: *logged.LogIndex,
	})
}

func verifyRekorSET(publicKey crypto.PublicKey, canonical, signature []byte) error {
	if publicKey.Algorithm == crypto.Ed25519 {
		return crypto.VerifyEd25519(publicKey.DER, canonical, signature)
	}
	return crypto.Verify(publicKey, canonical, signature, crypto.SignOptions{
		Hash: crypto.SHA256, RSAPadding: crypto.RSAPKCS1v15,
	})
}
