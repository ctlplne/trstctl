// SPDX-License-Identifier: BUSL-1.1

package scancollect

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

const (
	mediaOCIIndex      = "application/vnd.oci.image.index.v1+json"
	mediaOCIManifest   = "application/vnd.oci.image.manifest.v1+json"
	mediaDockerList    = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaDockerV2      = "application/vnd.docker.distribution.manifest.v2+json"
	maxRegistryLayer   = int64(2) << 30
	maxImageManifests  = 16
	maxTokenBodyBytes  = 64 << 10
	maxLayerFileBytes  = int64(64) << 20
	registryManifestAc = mediaOCIIndex + ", " + mediaOCIManifest + ", " + mediaDockerList + ", " + mediaDockerV2
)

var (
	registryRepository = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$`)
	registryTag        = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
	registryDigest     = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	challengeParam     = regexp.MustCompile(`(\w+)="([^"]*)"`)
)

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant,omitempty"`
	} `json:"platform,omitempty"`
}

type manifest struct {
	MediaType string       `json:"mediaType"`
	Config    descriptor   `json:"config"`
	Layers    []descriptor `json:"layers"`
	Manifests []descriptor `json:"manifests"`
}

// registryClient speaks the OCI distribution API for one repository, with the
// token-service challenge flow when the registry asks for it.
type registryClient struct {
	req    Request
	bearer string
}

// collectRegistry reads one image by tag or digest — every platform of an
// index, up to sixteen — and writes, under the image's manifest digest, each
// platform's config (its environment and build history) and the regular files
// of each layer. Blobs are checked against their digests before their content
// counts.
func collectRegistry(ctx context.Context, w *writer, req Request) (Result, error) {
	if !registryRepository.MatchString(req.Repository) || (!registryTag.MatchString(req.Reference) && !registryDigest.MatchString(req.Reference)) {
		return Result{}, fmt.Errorf("%w: a registry collection names a repository and a tag or sha256 digest", ErrRefused)
	}
	c := &registryClient{req: req}
	top, topDigest, err := c.manifest(ctx, req.Reference)
	if err != nil {
		return Result{}, err
	}
	if registryDigest.MatchString(req.Reference) && topDigest != req.Reference {
		return Result{}, fmt.Errorf("%w: the registry answered %s for %s", ErrRefused, topDigest, req.Reference)
	}
	res := Result{Object: map[string]string{"kind": "oci_image", "repository": req.Repository, "digest": topDigest}}
	images := []struct {
		m      manifest
		digest string
	}{{top, topDigest}}
	if len(top.Manifests) > 0 {
		images = images[:0]
		for i, d := range top.Manifests {
			if i == maxImageManifests || !registryDigest.MatchString(d.Digest) {
				res.Truncated = res.Truncated || i == maxImageManifests
				break
			}
			m, digest, err := c.manifest(ctx, d.Digest)
			if err != nil {
				return res, err
			}
			if digest != d.Digest {
				return res, fmt.Errorf("%w: platform manifest %s read back as %s", ErrRefused, d.Digest, digest)
			}
			images = append(images, struct {
				m      manifest
				digest string
			}{m, digest})
		}
	}
	root := "image-" + strings.TrimPrefix(topDigest, "sha256:")[:12]
	for _, image := range images {
		dir := root + "/" + strings.TrimPrefix(image.digest, "sha256:")[:12]
		if res.Items >= req.MaxItems {
			res.Truncated = true
			break
		}
		if registryDigest.MatchString(image.m.Config.Digest) {
			config, err := c.blob(ctx, image.m.Config)
			if err != nil {
				return res, err
			}
			ok, err := w.write(dir+"/config.json", config)
			secret.Wipe(config)
			if err != nil {
				return res, err
			}
			if ok {
				res.Items++
			}
		}
		for i, layer := range image.m.Layers {
			if res.Items >= req.MaxItems || w.full {
				res.Truncated = true
				break
			}
			if err := c.layer(ctx, w, fmt.Sprintf("%s/layer-%d", dir, i), layer); err != nil {
				return res, err
			}
			res.Items++
		}
	}
	return res, nil
}

func (c *registryClient) url(kind, ref string) string {
	return c.req.BaseURL + "/v2/" + c.req.Repository + "/" + kind + "/" + url.PathEscape(ref)
}

// do sends one GET, answering the registry's authentication challenge once.
func (c *registryClient) do(ctx context.Context, target, accept string) (*http.Response, error) {
	send := func() (*http.Response, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		if accept != "" {
			r.Header.Set("Accept", accept)
		}
		switch {
		case c.bearer != "":
			r.Header.Set("Authorization", c.bearer)
		case len(c.req.Token) > 0 && c.req.Username == "":
			r.Header.Set("Authorization", authorization(c.req).Get("Authorization"))
		}
		return c.req.Doer.Do(r)
	}
	resp, err := send()
	if err != nil || resp.StatusCode != http.StatusUnauthorized || c.bearer != "" {
		return resp, err
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBytes))
	_ = resp.Body.Close()
	switch {
	case strings.HasPrefix(strings.ToLower(challenge), "bearer "):
		if err := c.token(ctx, challenge); err != nil {
			return nil, err
		}
	case strings.HasPrefix(strings.ToLower(challenge), "basic ") && c.req.Username != "":
		c.bearer = basic(c.req.Username, c.req.Token)
	default:
		return nil, fmt.Errorf("%w: the registry requires credentials it was not given", ErrRefused)
	}
	return send()
}

// token answers a Bearer challenge at the registry's token service, with the
// username and token as basic credentials when they are given.
func (c *registryClient) token(ctx context.Context, challenge string) error {
	params := map[string]string{}
	for _, m := range challengeParam.FindAllStringSubmatch(challenge, -1) {
		params[strings.ToLower(m[1])] = m[2]
	}
	realm, err := url.Parse(params["realm"])
	if err != nil || (realm.Scheme != "https" && realm.Scheme != "http") || realm.Host == "" {
		return fmt.Errorf("%w: the registry's token service %q is not a URL", ErrRefused, params["realm"])
	}
	q := realm.Query()
	if params["service"] != "" {
		q.Set("service", params["service"])
	}
	q.Set("scope", "repository:"+c.req.Repository+":pull")
	realm.RawQuery = q.Encode()
	header := http.Header{}
	if c.req.Username != "" {
		header.Set("Authorization", basic(c.req.Username, c.req.Token))
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return err
	}
	r.Header = header
	resp, err := c.req.Doer.Do(r)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return statusError(resp.StatusCode, realm.String())
	}
	body, err := secret.ReadBounded(resp.Body, maxTokenBodyBytes)
	if err != nil {
		return err
	}
	defer secret.Wipe(body)
	var answer struct {
		Token       secret.JSONBytes `json:"token"`
		AccessToken secret.JSONBytes `json:"access_token"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		return fmt.Errorf("scancollect: registry token service answer: %w", err)
	}
	defer secret.Wipe(answer.Token)
	defer secret.Wipe(answer.AccessToken)
	token := answer.Token
	if len(token) == 0 {
		token = answer.AccessToken
	}
	if len(token) == 0 {
		return fmt.Errorf("%w: the registry's token service issued no token", ErrRefused)
	}
	c.bearer = authorization(Request{Token: token}).Get("Authorization")
	return nil
}

// manifest reads one manifest and returns it with its digest, computed over
// the bytes received.
func (c *registryClient) manifest(ctx context.Context, ref string) (manifest, string, error) {
	resp, err := c.do(ctx, c.url("manifests", ref), registryManifestAc)
	if err != nil {
		return manifest{}, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return manifest{}, "", statusError(resp.StatusCode, c.url("manifests", ref))
	}
	body, err := secret.ReadBounded(resp.Body, maxResponseBytes)
	if err != nil {
		return manifest{}, "", err
	}
	digest := "sha256:" + crypto.SHA256Hex(body)
	var m manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return manifest{}, "", fmt.Errorf("scancollect: manifest %s: %w", ref, err)
	}
	if m.MediaType == "" {
		m.MediaType = resp.Header.Get("Content-Type")
	}
	return m, digest, nil
}

// blob reads a small blob (an image config) and checks its digest.
func (c *registryClient) blob(ctx context.Context, d descriptor) ([]byte, error) {
	resp, err := c.do(ctx, c.url("blobs", d.Digest), "")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return nil, statusError(resp.StatusCode, c.url("blobs", d.Digest))
	}
	body, err := secret.ReadBounded(resp.Body, maxResponseBytes)
	if err != nil {
		return nil, err
	}
	if "sha256:"+crypto.SHA256Hex(body) != d.Digest {
		secret.Wipe(body)
		return nil, fmt.Errorf("%w: blob %s does not match its digest", ErrRefused, d.Digest)
	}
	return body, nil
}

// layer writes the regular files of one gzip (or plain) tar layer. The layer
// is read once: its bytes feed the digest and the tar reader together, and a
// layer whose digest does not match fails the collection.
func (c *registryClient) layer(ctx context.Context, w *writer, dir string, d descriptor) error {
	if !registryDigest.MatchString(d.Digest) || d.Size < 0 || d.Size > maxRegistryLayer {
		return fmt.Errorf("%w: layer %s is not a bounded sha256 blob", ErrRefused, d.Digest)
	}
	resp, err := c.do(ctx, c.url("blobs", d.Digest), "")
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return statusError(resp.StatusCode, c.url("blobs", d.Digest))
	}
	digest := crypto.NewSHA256HMACDigest(nil)
	body := io.TeeReader(io.LimitReader(resp.Body, maxRegistryLayer+1), digest)
	stream := body
	switch {
	case strings.HasSuffix(d.MediaType, "+gzip"), strings.HasSuffix(d.MediaType, ".tar.gzip"):
		gz, err := gzip.NewReader(body)
		if err != nil {
			return fmt.Errorf("scancollect: layer %s: %w", d.Digest, err)
		}
		defer func() { _ = gz.Close() }()
		stream = gz
	case strings.HasSuffix(d.MediaType, ".tar"), strings.HasSuffix(d.MediaType, "+tar"):
	default:
		// A compression this collector does not read (zstd) is skipped, and
		// its bytes still count against the digest check below.
		_, _ = io.Copy(io.Discard, body)
		return checkDigest(digest, d.Digest)
	}
	tr := tar.NewReader(stream)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("scancollect: layer %s: %w", d.Digest, err)
		}
		name := path.Clean("/" + hdr.Name)[1:]
		if hdr.Typeflag != tar.TypeReg || name == "" || strings.Contains(path.Base(name), ".wh.") || hdr.Size > maxLayerFileBytes {
			continue
		}
		if _, err := w.copyFrom(dir+"/"+name, tr, hdr.Size); err != nil {
			return err
		}
	}
	// Drain what follows the tar end so the digest covers the whole blob.
	_, _ = io.Copy(io.Discard, body)
	return checkDigest(digest, d.Digest)
}

func checkDigest(digest *crypto.SHA256HMACDigest, want string) error {
	if "sha256:"+digest.SHA256Hex() != want {
		return fmt.Errorf("%w: layer %s does not match its digest", ErrRefused, want)
	}
	return nil
}
