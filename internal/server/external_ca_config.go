// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/adcs"
	"trstctl.com/trstctl/internal/ca/awspca"
	"trstctl.com/trstctl/internal/ca/azurekv"
	"trstctl.com/trstctl/internal/ca/digicert"
	"trstctl.com/trstctl/internal/ca/ejbca"
	"trstctl.com/trstctl/internal/ca/entrust"
	"trstctl.com/trstctl/internal/ca/gcpcas"
	"trstctl.com/trstctl/internal/ca/globalsign"
	"trstctl.com/trstctl/internal/ca/letsencrypt"
	"trstctl.com/trstctl/internal/ca/sectigo"
	"trstctl.com/trstctl/internal/ca/shellca"
	"trstctl.com/trstctl/internal/ca/smallstep"
	"trstctl.com/trstctl/internal/ca/vaultpki"
	"trstctl.com/trstctl/internal/ca/venafi"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/crypto/secretfile"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/signing"
)

// externalCAsFromConfig constructs only credential-free registry entries. Each
// entry's Factory loads credentials into locked memory immediately before one
// outbox delivery and destroys both the provider copy and the source buffers on
// every success/failure path. ACME account keys and remote CA/HSM private-key
// operations are opaque handles on SignerProvider; they never enter this process.
//
// upstreamDV may be nil. When it is non-nil, an ACME entry with upstream_dns01
// enabled gets a solver bound to that entry's own CAA issuer domain (epic B7).
func externalCAsFromConfig(ctx context.Context, items []config.ExternalCAConfig, signerProvider SignerProvider, tokenProvider signing.SignTokenProvider, guard *egress.Guard, upstreamDV *upstreamDVHolder) ([]ExternalCA, error) {
	if err := config.ValidateExternalCAs(items); err != nil {
		return nil, err
	}
	out := make([]ExternalCA, 0, len(items))
	for _, item := range items {
		item := item
		if item.Type != "shellca" && item.Type != "azurekv" && guard != nil && guard.Enabled() {
			if err := guard.CheckURL(externalCAConfigEndpoint(item)); err != nil {
				return nil, fmt.Errorf("external CA %q egress policy: %w", item.ID, err)
			}
		}
		var (
			acmeAccountSigner crypto.DigestSigner
			azureCASigner     crypto.DigestSigner
			err               error
		)
		if item.Type == "letsencrypt" {
			acmeAccountSigner, err = bindOrCreateACMEAccountSigner(ctx, signerProvider, item)
			if err != nil {
				return nil, fmt.Errorf("external CA %q ACME account custody: %w", item.ID, err)
			}
		}
		if item.Type == "azurekv" {
			azureCASigner, err = bindAzureManagedCASigner(signerProvider, tokenProvider, item)
			if err != nil {
				return nil, fmt.Errorf("external CA %q Azure CA custody: %w", item.ID, err)
			}
		}
		factory, err := externalCAFactoryFromConfig(item, guard, acmeAccountSigner, azureCASigner, upstreamDV)
		if err != nil {
			return nil, fmt.Errorf("external CA %q: %w", item.ID, err)
		}
		out = append(out, ExternalCA{ID: item.ID, Type: item.Type, Name: item.Name, TenantID: item.TenantID, Endpoint: item.Endpoint, Factory: factory})
	}
	return out, nil
}

func externalCAFactoryFromConfig(item config.ExternalCAConfig, guard *egress.Guard, acmeAccountSigner, azureCASigner crypto.DigestSigner, upstreamDV *upstreamDVHolder) (ExternalCAFactory, error) {
	poll, err := item.PollIntervalDuration()
	if err != nil {
		return nil, err
	}
	defaultTTL, err := item.DefaultTTLDuration()
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) (implementation ca.CA, cleanup func(), err error) {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		secrets := &externalCASecretSet{}
		var client *http.Client
		var clientCleanup func()
		finish := func() {
			if d, ok := implementation.(interface{ Destroy() }); ok {
				d.Destroy()
			}
			secrets.Destroy()
			if client != nil {
				client.CloseIdleConnections()
			}
			if clientCleanup != nil {
				clientCleanup()
			}
		}
		fail := func(buildErr error) (ca.CA, func(), error) {
			finish()
			return nil, nil, buildErr
		}
		if item.Type != "shellca" && item.Type != "azurekv" {
			client, clientCleanup, err = externalCAHTTPClient(externalCAConfigEndpoint(item), item.Network, guard)
			if err != nil {
				return fail(err)
			}
		}
		switch item.Type {
		case "adcs":
			password, loadErr := secrets.LoadOptional(item.PasswordRef)
			if loadErr != nil {
				return fail(loadErr)
			}
			transport, buildErr := adcs.NewWebEnrollmentTransport(adcs.WebEnrollmentConfig{
				BaseURL: item.Endpoint, Username: item.Username, Password: password, HTTPClient: client, Timeout: client.Timeout,
			})
			if buildErr != nil {
				return fail(buildErr)
			}
			opts := []adcs.Option{}
			if poll > 0 {
				opts = append(opts, adcs.WithPollInterval(poll))
			}
			implementation = adcs.New(adcs.Config{Name: item.Name, CAConfig: item.CAConfig, Template: item.Template}, transport, opts...)
		case "awspca":
			secretKey, loadErr := secrets.Load(item.SecretAccessKeyRef)
			if loadErr != nil {
				return fail(loadErr)
			}
			sessionToken, loadErr := secrets.LoadOptional(item.SessionTokenRef)
			if loadErr != nil {
				return fail(loadErr)
			}
			api, buildErr := awspca.NewHTTPAPI(awspca.HTTPConfig{
				Endpoint: item.Endpoint, Region: item.Region, AccessKeyID: item.AccessKeyID,
				SecretAccessKey: secretKey, SessionToken: sessionToken, HTTPClient: client, Timeout: client.Timeout,
			})
			if buildErr != nil {
				return fail(buildErr)
			}
			opts := []awspca.Option{}
			if poll > 0 {
				opts = append(opts, awspca.WithPollInterval(poll))
			}
			implementation = awspca.New(awspca.Config{
				Name: item.Name, CertificateAuthorityArn: item.CertificateAuthorityARN, SigningAlgorithm: item.SigningAlgorithm,
			}, api, opts...)
		case "azurekv":
			if azureCASigner == nil {
				return fail(errors.New("isolated managed-key signer is required for Azure CA"))
			}
			caChain, readErr := os.ReadFile(item.CACertFile)
			if readErr != nil {
				return fail(fmt.Errorf("read Azure CA certificate chain: %w", readErr))
			}
			if len(caChain) == 0 || len(caChain) > 4<<20 {
				return fail(errors.New("invalid Azure CA certificate chain size"))
			}
			built, buildErr := azurekv.NewKeysCA(azurekv.KeysCAConfig{
				Name: item.Name, CACertificatePEM: caChain, DefaultTTL: defaultTTL,
			}, azureCASigner, nil)
			if buildErr != nil {
				return fail(buildErr)
			}
			implementation = built
		case "digicert", "ejbca", "entrust", "globalsign", "sectigo", "smallstep", "vaultpki", "venafi":
			implementation, err = buildCommercialExternalCA(item, poll, defaultTTL, client, secrets)
			if err != nil {
				return fail(err)
			}
		case "gcpcas":
			token, loadErr := secrets.Load(item.BearerTokenRef)
			if loadErr != nil {
				return fail(loadErr)
			}
			api, buildErr := gcpcas.NewHTTPAPI(gcpcas.HTTPConfig{Endpoint: item.Endpoint, BearerToken: token, HTTPClient: client, Timeout: client.Timeout})
			if buildErr != nil {
				return fail(buildErr)
			}
			implementation = gcpcas.New(gcpcas.Config{Name: item.Name, CaPool: item.CAPool}, api)
		case "letsencrypt":
			if acmeAccountSigner == nil {
				return fail(errors.New("isolated ACME account signer is required for Let's Encrypt"))
			}
			var acmeOpts []letsencrypt.Option
			if item.UpstreamDNS01 && upstreamDV != nil {
				// Bound to THIS authority's CAA identifier, not a
				// process-wide one — see upstreamDVHolder.
				binding := upstreamDV.bind(item.CAAIssuerDomain, item.ID)
				acmeOpts = append(acmeOpts,
					letsencrypt.WithChallengeSolver(binding),
					letsencrypt.WithDVObserver(binding))
			}
			implementation, err = letsencrypt.NewPluginWithRemoteAccountSigner(item.Name, externalCAConfigEndpoint(item), client, acmeAccountSigner, acmeOpts...)
			if err != nil {
				return fail(err)
			}
		case "shellca":
			implementation, err = buildShellExternalCA(item, secrets)
			if err != nil {
				return fail(err)
			}
		default:
			return fail(fmt.Errorf("unsupported external CA type %q", item.Type))
		}
		return implementation, finish, nil
	}, nil
}

// buildCommercialExternalCA keeps credential-bearing vendor construction in a
// bounded stage. The caller owns the secret set and destroys it together with
// the returned implementation after the one outbox delivery.
func buildCommercialExternalCA(item config.ExternalCAConfig, poll, defaultTTL time.Duration, client *http.Client, secrets *externalCASecretSet) (ca.CA, error) {
	switch item.Type {
	case "digicert":
		apiKey, err := secrets.Load(item.APIKeyRef)
		if err != nil {
			return nil, err
		}
		opts := []digicert.Option{digicert.WithHTTPClient(client)}
		if item.Product != "" {
			opts = append(opts, digicert.WithProduct(item.Product))
		}
		return digicert.New(item.Name, item.Endpoint, apiKey, opts...), nil
	case "ejbca":
		token, err := secrets.LoadOptional(item.BearerTokenRef)
		if err != nil {
			return nil, err
		}
		password, err := secrets.LoadOptional(item.PasswordRef)
		if err != nil {
			return nil, err
		}
		return ejbca.New(ejbca.Config{
			Name: item.Name, BaseURL: item.Endpoint, Token: token, CAName: item.CAName,
			CertificateProfile: item.CertificateProfile, EndEntityProfile: item.EndEntityProfile,
			Username: item.Username, Password: password,
		}, ejbca.WithHTTPClient(client)), nil
	case "entrust":
		opts := []entrust.Option{entrust.WithHTTPClient(client)}
		if poll > 0 {
			opts = append(opts, entrust.WithPollInterval(poll))
		}
		return entrust.New(entrust.Config{
			Name: item.Name, BaseURL: item.Endpoint, CAID: item.CAID, ProfileID: item.ProfileID,
		}, opts...), nil
	case "globalsign":
		apiKey, err := secrets.Load(item.APIKeyRef)
		if err != nil {
			return nil, err
		}
		apiSecret, err := secrets.Load(item.APISecretRef)
		if err != nil {
			return nil, err
		}
		opts := []globalsign.Option{globalsign.WithHTTPClient(client)}
		if poll > 0 {
			opts = append(opts, globalsign.WithPollInterval(poll))
		}
		return globalsign.New(globalsign.Config{
			Name: item.Name, BaseURL: item.Endpoint, APIKey: apiKey, APISecret: apiSecret,
		}, opts...), nil
	case "sectigo":
		password, err := secrets.Load(item.PasswordRef)
		if err != nil {
			return nil, err
		}
		opts := []sectigo.Option{sectigo.WithHTTPClient(client)}
		if poll > 0 {
			opts = append(opts, sectigo.WithPollInterval(poll))
		}
		return sectigo.New(sectigo.Config{
			Name: item.Name, BaseURL: item.Endpoint, Login: item.Login, Password: password,
			CustomerURI: item.CustomerURI, OrgID: item.OrgID, CertType: item.CertType,
		}, opts...), nil
	case "smallstep":
		key, err := secrets.Load(item.ProvisionerKeyRef)
		if err != nil {
			return nil, err
		}
		return smallstep.New(smallstep.Config{
			Name: item.Name, BaseURL: item.Endpoint, ProvisionerName: item.ProvisionerName, ProvisionerKey: key,
		}, smallstep.WithHTTPClient(client)), nil
	case "vaultpki":
		token, err := secrets.Load(item.BearerTokenRef)
		if err != nil {
			return nil, err
		}
		return vaultpki.New(vaultpki.Config{
			Name: item.Name, BaseURL: item.Endpoint, Token: token, Mount: item.Mount, Role: item.Role, DefaultTTL: defaultTTL,
		}, vaultpki.WithHTTPClient(client)), nil
	case "venafi":
		token, err := secrets.Load(item.AccessTokenRef)
		if err != nil {
			return nil, err
		}
		opts := []venafi.Option{venafi.WithHTTPClient(client)}
		if poll > 0 {
			opts = append(opts, venafi.WithPollInterval(poll))
		}
		return venafi.New(venafi.Config{
			Name: item.Name, BaseURL: item.Endpoint, AccessToken: token,
			PolicyDN: item.PolicyDN, Application: item.Application,
		}, opts...), nil
	default:
		return nil, fmt.Errorf("unsupported commercial external CA type %q", item.Type)
	}
}

func buildShellExternalCA(item config.ExternalCAConfig, secrets *externalCASecretSet) (ca.CA, error) {
	names := make([]string, 0, len(item.EnvRefs))
	for name := range item.EnvRefs {
		names = append(names, name)
	}
	sort.Strings(names)
	secretFDs := make([]shellca.SecretFD, 0, len(names))
	for _, name := range names {
		value, err := secrets.Load(item.EnvRefs[name])
		if err != nil {
			return nil, err
		}
		secretFDs = append(secretFDs, shellca.SecretFD{Name: name, Value: value})
	}
	timeout, err := item.Network.TimeoutDuration()
	if err != nil {
		return nil, err
	}
	return shellca.New(shellca.Config{
		Name: item.Name, Command: item.Command, Args: append([]string(nil), item.Args...), SecretFDs: secretFDs, Timeout: timeout,
	}), nil
}

func bindOrCreateACMEAccountSigner(ctx context.Context, provider SignerProvider, item config.ExternalCAConfig) (crypto.DigestSigner, error) {
	if provider == nil || provider.Client() == nil {
		return nil, errors.New("isolated signing service is required")
	}
	client := provider.Client()
	identity := strings.TrimSpace(item.ID) + "\x00" + externalCAConfigEndpoint(item)
	handle := "acme-account-" + crypto.SHA256Hex([]byte(identity))[:32]
	bind := func() (*signing.RemoteSigner, error) {
		return client.SignerForHandleWithPurpose(ctx, handle, signing.PurposeACMEAccount)
	}
	remote, err := bind()
	if err == nil {
		if remote.Algorithm() != crypto.ECDSAP256 {
			return nil, fmt.Errorf("existing signer handle %q uses %s, want ECDSA-P256", handle, remote.Algorithm())
		}
		return remote, nil
	}
	if status.Code(err) != codes.NotFound {
		return nil, fmt.Errorf("bind signer handle %q: %w", handle, err)
	}
	remote, err = client.GenerateConstrainedKeyHandle(ctx, crypto.ECDSAP256, handle,
		[]signing.KeyPurpose{signing.PurposeACMEAccount}, signing.PurposeACMEAccount)
	if status.Code(err) == codes.AlreadyExists {
		remote, err = bind()
	}
	if err != nil {
		return nil, fmt.Errorf("provision signer handle %q: %w", handle, err)
	}
	return remote, nil
}

func bindAzureManagedCASigner(provider SignerProvider, tokenProvider signing.SignTokenProvider, item config.ExternalCAConfig) (crypto.DigestSigner, error) {
	if provider == nil || provider.Client() == nil {
		return nil, errors.New("isolated signing service is required")
	}
	if tokenProvider == nil {
		return nil, errors.New("independent managed-key sign-token provider is required")
	}
	chain, err := os.ReadFile(item.CACertFile)
	if err != nil {
		return nil, fmt.Errorf("read Azure CA certificate chain: %w", err)
	}
	if len(chain) == 0 || len(chain) > 4<<20 {
		return nil, errors.New("invalid Azure CA certificate chain size")
	}
	block, _ := pem.Decode(chain)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("certificate chain for Azure CA must start with a CERTIFICATE PEM block")
	}
	publicDER, err := crypto.PublicKeyDERFromCert(block.Bytes)
	if err != nil {
		return nil, err
	}
	public, err := crypto.ParsePublicKeyPEM(crypto.MarshalPublicKeyPEM(publicDER))
	if err != nil {
		return nil, fmt.Errorf("classify Azure CA public key: %w", err)
	}
	return provider.Client().SignerForManagedKey(
		strings.TrimSpace(item.TenantID), "azure-key-vault", strings.TrimSpace(item.ManagedKeyRef), public.Algorithm, public.DER,
		signing.PurposeCASign, tokenProvider,
	)
}

type externalCASecretSet struct {
	buffers []*secret.Buffer
}

func (s *externalCASecretSet) Load(ref string) ([]byte, error) {
	path, ok := strings.CutPrefix(strings.TrimSpace(ref), "file:")
	if !ok || strings.TrimSpace(path) == "" {
		return nil, errors.New("external CA credential reference must use file:/absolute/path")
	}
	raw, err := secretfile.Load(path)
	if err != nil {
		return nil, fmt.Errorf("load external CA credential file: %w", err)
	}
	trimmed := bytes.TrimRight(raw, "\r\n")
	buffer, err := secret.NewFrom(trimmed)
	secret.Wipe(raw)
	if err != nil {
		return nil, fmt.Errorf("lock external CA credential: %w", err)
	}
	s.buffers = append(s.buffers, buffer)
	return buffer.Bytes(), nil
}

func (s *externalCASecretSet) LoadOptional(ref string) ([]byte, error) {
	if strings.TrimSpace(ref) == "" {
		return nil, nil
	}
	return s.Load(ref)
}

func (s *externalCASecretSet) Destroy() {
	for i := len(s.buffers) - 1; i >= 0; i-- {
		s.buffers[i].Destroy()
	}
	s.buffers = nil
}

func externalCAHTTPClient(endpoint string, network config.ExternalCANetworkConfig, guard *egress.Guard) (*http.Client, func(), error) {
	prefixes, err := network.PrivatePrefixes()
	if err != nil {
		return nil, nil, err
	}
	timeout, err := network.TimeoutDuration()
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() {}
	if network.AllowInsecureHTTP {
		client := netsec.InsecureLoopbackClient(timeout)
		if guard != nil {
			client.Transport = guard.WrapTransport(client.Transport)
		}
		client.Transport, err = netsec.BindTransportToOrigin(endpoint, client.Transport)
		if err != nil {
			return nil, nil, err
		}
		return client, cleanup, nil
	}
	safe := netsec.SafeTransportWithOptions(netsec.SafeClientOptions{AllowPrivateCIDRs: prefixes})
	transport := safe
	if network.RootCAFile != "" {
		rootPEM, err := os.ReadFile(network.RootCAFile)
		if err != nil {
			return nil, nil, fmt.Errorf("read external CA root: %w", err)
		}
		var trusted *http.Transport
		if network.ClientCertFile != "" {
			identity, err := mtls.LoadAgentIdentity("external-ca-client", network.ClientKeyFile, network.ClientCertFile)
			if err != nil {
				return nil, nil, fmt.Errorf("load external CA mTLS identity: %w", err)
			}
			cleanup = identity.Destroy
			trusted, err = mtls.AgentHTTPTransport(identity, rootPEM, network.ServerName, nil)
			if err != nil {
				cleanup()
				return nil, nil, fmt.Errorf("build external CA mTLS transport: %w", err)
			}
		} else {
			trusted, err = mtls.HTTPTransportForServerName(rootPEM, network.ServerName)
			if err != nil {
				return nil, nil, fmt.Errorf("build external CA trusted transport: %w", err)
			}
		}
		// Preserve the crypto boundary's TLS configuration while replacing its
		// dial path with the resolved-address SSRF guard.
		trusted.DialContext = safe.DialContext
		trusted.DialTLSContext = nil
		trusted.TLSHandshakeTimeout = safe.TLSHandshakeTimeout
		trusted.ResponseHeaderTimeout = safe.ResponseHeaderTimeout
		trusted.DisableKeepAlives = true
		transport = trusted
	}
	roundTripper := http.RoundTripper(transport)
	if guard != nil {
		roundTripper = guard.WrapTransport(roundTripper)
	}
	roundTripper, err = netsec.BindTransportToOrigin(endpoint, roundTripper)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return &http.Client{
		Timeout: timeout, Transport: roundTripper,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("%w: external CA redirect limit exceeded", netsec.ErrSSRFBlocked)
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("%w: external CA redirect uses unsupported scheme", netsec.ErrSSRFBlocked)
			}
			if len(via) > 0 {
				previous := via[len(via)-1].URL
				if !strings.EqualFold(req.URL.Scheme, previous.Scheme) || !strings.EqualFold(req.URL.Host, previous.Host) {
					return fmt.Errorf("%w: external CA cross-origin or scheme-changing redirect rejected", netsec.ErrSSRFBlocked)
				}
			}
			if ip := net.ParseIP(req.URL.Hostname()); ip != nil && netsec.BlockedIP(ip) && !prefixContains(prefixes, ip) {
				return fmt.Errorf("%w: redirect to %s", netsec.ErrSSRFBlocked, req.URL.Hostname())
			}
			if guard != nil {
				return guard.CheckRequestURL(req.URL)
			}
			return nil
		},
	}, cleanup, nil
}

func prefixContains(prefixes []netip.Prefix, ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func externalCAConfigEndpoint(item config.ExternalCAConfig) string {
	if item.Type == "letsencrypt" && strings.TrimSpace(item.DirectoryURL) != "" {
		return strings.TrimSpace(item.DirectoryURL)
	}
	return strings.TrimSpace(item.Endpoint)
}
