// SPDX-License-Identifier: MPL-2.0

package mtls

import (
	"bytes"
	"context"
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/credentials"
	boundary "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// RenewingServerCertificate renews a listener's public leaf without changing its
// local key, trusted CA or live connections. The CA signing callback remains at
// the caller's existing signer boundary; only a public CSR crosses that boundary.
// One Run worker renews before expiry; handshakes never wait for the CA.
// The local transport key stays in a locked buffer and is destroyed on Close.
type RenewingServerCertificate struct {
	key     *boundary.LockedSigner
	signer  *serverDigestSigner
	csr     []byte
	roots   *x509.CertPool
	hosts   []string
	issue   func([]byte) ([]byte, error)
	current atomic.Pointer[tls.Certificate]
	closed  atomic.Bool
	renewAt time.Time // constructor and the single Run worker only
}

type serverDigestSigner struct {
	key    *boundary.LockedSigner
	public stdcrypto.PublicKey
}

func (s *serverDigestSigner) Public() stdcrypto.PublicKey { return s.public }
func (s *serverDigestSigner) Sign(_ io.Reader, digest []byte, opts stdcrypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != stdcrypto.SHA256 || len(digest) != stdcrypto.SHA256.Size() {
		return nil, errors.New("mtls: P-256 server signature requires SHA-256")
	}
	return s.key.SignDigest(digest, boundary.SignOptions{Hash: boundary.SHA256})
}

// NewRenewingServerCertificate obtains and verifies the first leaf before a
// listener starts. issue must be bounded (the isolated signer's RPC has a 30s
// deadline). It is called serially, never by a handshake or an unbounded queue.
func NewRenewingServerCertificate(caPEM []byte, hosts []string, issue func([]byte) ([]byte, error)) (*RenewingServerCertificate, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) || len(hosts) == 0 || issue == nil {
		return nil, errors.New("mtls: server renewal requires a CA, hosts and issuer")
	}
	key, err := boundary.GenerateLockedKey(boundary.ECDSAP256)
	if err != nil {
		return nil, err
	}
	public, err := x509.ParsePKIXPublicKey(key.Public().DER)
	if err != nil {
		key.Destroy()
		return nil, err
	}
	r := &RenewingServerCertificate{key: key, signer: &serverDigestSigner{key: key, public: public}, roots: roots, hosts: append([]string(nil), hosts...), issue: issue}
	r.csr, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: hosts[0]}}, r.signer)
	if err == nil {
		err = r.renew()
	}
	if err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

func (r *RenewingServerCertificate) renew() error {
	chain, err := r.issue(append([]byte(nil), r.csr...))
	if err != nil {
		return err
	}
	if len(chain) > certinfo.MaxPublicChainBytes {
		return errors.New("mtls: renewed server chain exceeds the public-chain limit")
	}
	leafDER, err := FirstCertDER(chain)
	if err != nil {
		return err
	}
	chain, err = certinfo.ParsePublicPEMChain(chain, leafDER)
	if err != nil {
		return err
	}
	var ders [][]byte
	rest := chain
	for len(bytes.TrimSpace(rest)) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return errors.New("mtls: invalid renewed server chain")
		}
		ders = append(ders, block.Bytes)
		rest = remaining
	}
	if len(ders) == 0 {
		return errors.New("mtls: renewed server chain is empty")
	}
	leaf, err := x509.ParseCertificate(ders[0])
	if err != nil {
		return fmt.Errorf("mtls: renewed server leaf: %w", err)
	}
	public, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(public, r.key.Public().DER) {
		return errors.New("mtls: renewed server leaf has a different key")
	}
	intermediate := x509.NewCertPool()
	for _, der := range ders[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		intermediate.AddCert(cert)
	}
	now := time.Now()
	for _, host := range r.hosts {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: r.roots, Intermediates: intermediate, CurrentTime: now, DNSName: host, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			return fmt.Errorf("mtls: verify renewed server leaf: %w", err)
		}
	}
	if leaf.IsCA || leaf.NotAfter.Sub(now) < 2*time.Second {
		return errors.New("mtls: renewed server leaf has no usable lifetime")
	}
	if old := r.current.Load(); old != nil && !leaf.NotAfter.After(old.Leaf.NotAfter) {
		return errors.New("mtls: renewed server leaf does not extend expiry")
	}
	r.current.Store(&tls.Certificate{Certificate: ders, PrivateKey: r.signer, Leaf: leaf})
	// Use actual remaining validity, not the requested TTL or a backdated NotBefore.
	r.renewAt = now.Add(leaf.NotAfter.Sub(now) / 2)
	return nil
}

// NotAfter is the current verified leaf's expiry, suitable for a low-cardinality
// listener metric. It contains no tenant, private key or payload data.
func (r *RenewingServerCertificate) NotAfter() time.Time {
	if c := r.current.Load(); c != nil {
		return c.Leaf.NotAfter
	}
	return time.Time{}
}

// Run owns one renewal loop. A failure keeps the previous leaf until its actual
// expiry and retries at most once per second, at most 30s apart. Recovery needs
// no listener restart. Call Close after the listener and this worker stop.
func (r *RenewingServerCertificate) Run(ctx context.Context, observe func(time.Time, error)) {
	next := r.renewAt
	for {
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if ctx.Err() != nil || r.closed.Load() {
			return
		}
		err := r.renew()
		if observe != nil {
			observe(r.NotAfter(), err)
		}
		if err == nil {
			next = r.renewAt
			continue
		}
		retry := time.Until(r.NotAfter()) / 8
		if retry < time.Second {
			retry = time.Second
		}
		if retry > 30*time.Second {
			retry = 30 * time.Second
		}
		next = time.Now().Add(retry)
	}
}

func (r *RenewingServerCertificate) certificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := r.current.Load()
	if r.closed.Load() || c == nil || !time.Now().Before(c.Leaf.NotAfter) {
		return nil, errors.New("mtls: agent listener server certificate is unavailable or expired")
	}
	return c, nil
}

// TLSConfig retains the TLS1.3 and verified-client-certificate requirements of
// the static agent listener. No fallback or verification bypass is installed.
func (r *RenewingServerCertificate) TLSConfig() *tls.Config {
	cfg := serverTLSConfig(tls.Certificate{}, r.roots)
	cfg.Certificates = nil
	cfg.GetCertificate = r.certificate
	return cfg
}

// Credentials is the same renewing identity for the gRPC agent listener.
func (r *RenewingServerCertificate) Credentials() credentials.TransportCredentials {
	return credentials.NewTLS(r.TLSConfig())
}

// Close prevents new handshakes and zeroes the locked transport key. Concurrent
// in-flight signing uses LockedSigner's existing protected destruction boundary.
func (r *RenewingServerCertificate) Close() {
	if r.closed.CompareAndSwap(false, true) {
		r.key.Destroy()
	}
}
