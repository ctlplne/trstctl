package server

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// internalCertTTL is the validity of the self-signed internal server certificate.
const internalCertTTL = 365 * 24 * time.Hour

// serveControlPlane serves srv over ln according to the TLS configuration (B4).
// The default (internal) and file modes serve TLS, so no credential or session
// travels in cleartext; disabled serves plaintext and writes a loud warning to
// warn (local development only). It blocks until the server stops, and returns
// the serving error (nil on a clean shutdown via http.ErrServerClosed handling
// by the caller).
func serveControlPlane(srv *http.Server, ln net.Listener, tlsCfg config.TLS, warn io.Writer) error {
	switch tlsCfg.Mode {
	case config.TLSDisabled:
		_, _ = fmt.Fprintln(warn, "WARNING: serving the control plane over PLAINTEXT HTTP (server.tls.mode=disabled); credentials, tokens, and sessions travel in the clear — use only for local development")
		return srv.Serve(ln)
	case config.TLSFile:
		sc, err := mtls.ServerCertFromFiles(tlsCfg.CertFile, tlsCfg.KeyFile)
		if err != nil {
			return err
		}
		return sc.ServeHTTPS(srv, ln)
	default: // TLSInternal, and the zero value defensively
		sc, err := mtls.SelfSignedServerCert(serverHosts(), internalCertTTL)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintln(warn, "serving the control plane over TLS with a self-signed internal certificate (server.tls.mode=internal); trust it for evaluation, or set server.tls.mode=file with an operator certificate for production")
		return sc.ServeHTTPS(srv, ln)
	}
}

// serverHosts are the SAN hosts for the internal self-signed certificate:
// loopback, the conventional Compose service name, and the machine hostname, so
// the common ways an evaluator reaches the control plane verify.
func serverHosts() []string {
	hosts := []string{"localhost", "127.0.0.1", "::1", "trstctl"}
	if h, err := os.Hostname(); err == nil && h != "" {
		hosts = append(hosts, h)
	}
	return hosts
}
