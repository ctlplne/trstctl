// SPDX-License-Identifier: MPL-2.0

package mtls

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// defaultReloadCheckInterval bounds how often a TLS handshake may trigger a
// stat of the certificate/key files. Rotation tooling (cert-manager, certbot
// deploy hooks) replaces files seconds apart, so one second keeps rotation
// near-instant while a handshake flood stays O(1) stats per second.
const defaultReloadCheckInterval = time.Second

// reloadingServerCert atomically swaps an operator-provided certificate/key
// pair when the files change on disk (OPS-TLS-RELOAD-001). A failed or
// half-finished rotation keeps the previous good pair being served — TLS
// never degrades because a hook wrote files non-atomically.
type reloadingServerCert struct {
	certFile string
	keyFile  string

	interval  atomic.Int64 // nanoseconds between stat checks
	nextCheck atomic.Int64 // unix nanoseconds of the next allowed stat

	mu      sync.Mutex // serializes stat+reload; handshakes read `current`
	current atomic.Pointer[tls.Certificate]
	certMod time.Time
	keyMod  time.Time
}

func newReloadingServerCert(certFile, keyFile string) (*reloadingServerCert, error) {
	r := &reloadingServerCert{certFile: certFile, keyFile: keyFile}
	r.interval.Store(int64(defaultReloadCheckInterval))
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("mtls: load server certificate: %w", err)
	}
	certMod, keyMod, err := r.statPair()
	if err != nil {
		return nil, err
	}
	r.current.Store(&cert)
	r.certMod, r.keyMod = certMod, keyMod
	return r, nil
}

func (r *reloadingServerCert) statPair() (time.Time, time.Time, error) {
	certInfo, err := os.Stat(r.certFile)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("mtls: stat server certificate: %w", err)
	}
	keyInfo, err := os.Stat(r.keyFile)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("mtls: stat server key: %w", err)
	}
	return certInfo.ModTime(), keyInfo.ModTime(), nil
}

// GetCertificate is the tls.Config hook: it serves the current pair and, at
// most once per check interval, stats the files and hot-swaps a rotated pair.
func (r *reloadingServerCert) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	now := time.Now()
	next := r.nextCheck.Load()
	if now.UnixNano() >= next && r.nextCheck.CompareAndSwap(next, now.Add(time.Duration(r.interval.Load())).UnixNano()) {
		r.maybeReload()
	}
	if cert := r.current.Load(); cert != nil {
		return cert, nil
	}
	return nil, fmt.Errorf("mtls: no server certificate loaded")
}

func (r *reloadingServerCert) maybeReload() {
	r.mu.Lock()
	defer r.mu.Unlock()
	certMod, keyMod, err := r.statPair()
	if err != nil {
		return // half-rotation or transient FS error: keep serving the good pair
	}
	if certMod.Equal(r.certMod) && keyMod.Equal(r.keyMod) {
		return
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return // mismatched/corrupt pair mid-rotation: keep the good pair
	}
	r.current.Store(&cert)
	r.certMod, r.keyMod = certMod, keyMod
}

// SetReloadCheckInterval tightens or relaxes the stat window (tests use
// milliseconds; production keeps the 1s default). No-op for non-file certs.
func (s *ServerCert) SetReloadCheckInterval(interval time.Duration) {
	if s.reload == nil || interval <= 0 {
		return
	}
	s.reload.interval.Store(int64(interval))
	s.reload.nextCheck.Store(0)
}
