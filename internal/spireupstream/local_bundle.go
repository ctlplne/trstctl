// SPDX-License-Identifier: BUSL-1.1

package spireupstream

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"hash/fnv"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	typesv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A205-L3: SubscribeToLocalBundle hands SPIRE the trust domain's bundle as
// trstctl sees it: the root of the CA authority SPIRE's X.509 CA is signed
// under, and the JWT keys the tenant's SPIRE servers and trstctl itself
// (A205-L2) publish. SPIRE Server keeps its bundle's X.509 roots in step with
// it and adds the JWT keys, so a root trstctl rotates in, or a JWT key
// published by another server or by trstctl, reaches it without SPIRE minting
// or rotating anything.

// maxAuthorityDepth bounds the walk from the configured authority to its
// root, and maxAuthorityPages the authority listing.
const (
	maxAuthorityDepth = 16
	maxAuthorityPages = 64
)

// SubscribeToLocalBundle sends the bundle, then sends it again whenever the
// root or the key set changes, checked every jwt_key_refresh_seconds. A
// failed refresh keeps the stream open: SPIRE reopens it only after a new
// subscription, so the next refresh tries again.
func (p *Plugin) SubscribeToLocalBundle(_ *upstreamauthorityv1.SubscribeToLocalBundleRequest, stream upstreamauthorityv1.UpstreamAuthority_SubscribeToLocalBundleServer) error {
	cfg, client, err := p.currentConfig()
	if err != nil {
		return err
	}
	ctx := stream.Context()
	roots, keys, err := localBundle(ctx, cfg, client)
	if err != nil {
		return err
	}
	if err := stream.Send(&upstreamauthorityv1.SubscribeToLocalBundleResponse{UpstreamX509Roots: roots, UpstreamJwtKeys: keys}); err != nil {
		return err
	}
	last := localBundleDigest(roots, keys)
	ticker := time.NewTicker(time.Duration(cfg.JWTKeyRefreshSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		roots, keys, err := localBundle(ctx, cfg, client)
		if err != nil {
			continue
		}
		if digest := localBundleDigest(roots, keys); digest != last {
			if err := stream.Send(&upstreamauthorityv1.SubscribeToLocalBundleResponse{UpstreamX509Roots: roots, UpstreamJwtKeys: keys}); err != nil {
				return err
			}
			last = digest
		}
	}
}

// localBundle reads the configured authority's root and the JWT key set. A
// trstctl that does not serve JWT key publication contributes the root alone.
func localBundle(ctx context.Context, cfg *Config, client *http.Client) ([]*typesv1.X509Certificate, []*typesv1.JWTKey, error) {
	root, err := authorityRoot(ctx, cfg, client)
	if err != nil {
		return nil, nil, err
	}
	keys, err := listJWTKeys(ctx, cfg, client)
	if err != nil && status.Code(err) != codes.Unimplemented {
		return nil, nil, err
	}
	return []*typesv1.X509Certificate{{Asn1: root}}, keys, nil
}

// servedAuthority is one entry of GET /api/v1/ca/authorities as the plugin
// reads it.
type servedAuthority struct {
	ID             string  `json:"id"`
	ParentID       *string `json:"parent_id"`
	CertificatePEM string  `json:"certificate_pem"`
}

// authorityRoot walks from the configured CA authority up its parents to the
// root and returns the root certificate's DER.
func authorityRoot(ctx context.Context, cfg *Config, client *http.Client) ([]byte, error) {
	authorities, err := listAuthorities(ctx, cfg, client)
	if err != nil {
		return nil, err
	}
	id := cfg.CAAuthorityID
	for depth := 0; depth < maxAuthorityDepth; depth++ {
		authority, ok := authorities[id]
		if !ok {
			return nil, status.Errorf(codes.FailedPrecondition, "trstctl serves no CA authority %s for this token", id)
		}
		if authority.ParentID == nil || *authority.ParentID == "" {
			block, _ := pem.Decode([]byte(authority.CertificatePEM))
			if block == nil || block.Type != "CERTIFICATE" {
				return nil, status.Errorf(codes.Internal, "CA authority %s has no certificate", id)
			}
			return block.Bytes, nil
		}
		id = *authority.ParentID
	}
	return nil, status.Errorf(codes.FailedPrecondition, "CA authority %s is more than %d levels below a root", cfg.CAAuthorityID, maxAuthorityDepth)
}

// listAuthorities reads every page of GET /api/v1/ca/authorities.
func listAuthorities(ctx context.Context, cfg *Config, client *http.Client) (map[string]servedAuthority, error) {
	token, err := readTokenFile(cfg.TokenFile)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "read token file: %v", err)
	}
	defer zero(token)
	out := map[string]servedAuthority{}
	cursor := ""
	for page := 0; page < maxAuthorityPages; page++ {
		endpoint := cfg.Endpoint + "/api/v1/ca/authorities"
		if cursor != "" {
			endpoint += "?cursor=" + url.QueryEscape(cursor)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "build trstctl request: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+string(token))
		resp, err := client.Do(req)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "call trstctl: %v", err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		_ = resp.Body.Close()
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "read trstctl response: %v", err)
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return nil, status.Errorf(codes.Unavailable, "trstctl returned HTTP %d listing CA authorities: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		var listed struct {
			Items      []servedAuthority `json:"items"`
			NextCursor string            `json:"next_cursor"`
		}
		if err := json.Unmarshal(body, &listed); err != nil {
			return nil, status.Errorf(codes.Internal, "decode trstctl CA authorities: %v", err)
		}
		for _, authority := range listed.Items {
			out[authority.ID] = authority
		}
		if listed.NextCursor == "" {
			return out, nil
		}
		cursor = listed.NextCursor
	}
	return nil, status.Errorf(codes.FailedPrecondition, "trstctl lists more than %d pages of CA authorities", maxAuthorityPages)
}

// localBundleDigest identifies a bundle so the stream sends only changes.
func localBundleDigest(roots []*typesv1.X509Certificate, keys []*typesv1.JWTKey) uint64 {
	h := fnv.New64a()
	for _, root := range roots {
		_, _ = h.Write(root.GetAsn1())
		_, _ = h.Write([]byte{0})
	}
	var digest [8]byte
	binary.BigEndian.PutUint64(digest[:], jwtKeySetDigest(keys))
	_, _ = h.Write(digest[:])
	return h.Sum64()
}
