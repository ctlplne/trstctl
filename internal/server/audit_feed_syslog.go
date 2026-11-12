// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
)

// Syslog audit feeds (P5) deliver over TLS (RFC 5425). The receiver's
// certificate is verified against the system roots, or against the CA
// certificate a destination's token_ref names, and a receiver that requires
// mutual TLS is shown the certificate client_cert_ref names (P5-L2); the dial
// passes through the same egress guard as the HTTP collectors. Syslog acknowledges nothing per
// message, so a batch is delivered once every framed message is written and
// the TLS session is closed cleanly; a retry after a broken connection resends
// the whole batch, and each message carries its audit sequence, so the
// receiver can drop a repeat.

// syslogFeedTimeout bounds one delivery: dial, handshake and write.
var syslogFeedTimeout = 30 * time.Second

// deliverSyslogBatch writes the framed batch over one verified TLS session.
func deliverSyslogBatch(ctx context.Context, batch auditsink.FeedBatch, payload []byte) (string, error) {
	addr, serverName, err := auditsink.SyslogEndpoint(batch.EndpointURL)
	if err != nil {
		return "", fmt.Errorf("server: audit feed endpoint rejected: %w", err)
	}
	opts := netsec.SafeClientOptions{}
	if batch.AllowPrivateEndpoint {
		if opts, err = privateEgressSafeClientOptions(batch.PrivateEgressCIDRs); err != nil {
			return "", fmt.Errorf("server: audit feed endpoint rejected: %w", err)
		}
	}
	var caPEM []byte
	if strings.TrimSpace(batch.TokenRef) != "" {
		if caPEM, err = resolveDiscoveryCredentialBytesRef(ctx, batch.TokenRef); err != nil {
			return "", fmt.Errorf("server: resolve audit feed credential reference: %w", err)
		}
		defer secret.Wipe(caPEM)
	}
	// P5-L2: a receiver that requires mutual TLS gets the client certificate
	// and key client_cert_ref names; the bundle is wiped after the dial.
	var clientPEM []byte
	if strings.TrimSpace(batch.ClientCertRef) != "" {
		if clientPEM, err = resolveDiscoveryCredentialBytesRef(ctx, batch.ClientCertRef); err != nil {
			return "", fmt.Errorf("server: resolve audit feed client certificate reference: %w", err)
		}
		defer secret.Wipe(clientPEM)
	}
	dialCtx, cancel := context.WithTimeout(ctx, syslogFeedTimeout)
	defer cancel()
	conn, err := mtls.DialVerifiedTCPWithClientCert(dialCtx, addr, serverName, caPEM, clientPEM, netsec.SafeDialControlWithOptions(opts))
	if err != nil {
		return "", fmt.Errorf("server: audit feed collector request failed: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(syslogFeedTimeout)); err != nil {
		return "", fmt.Errorf("server: audit feed collector request failed: %w", err)
	}
	if _, err := conn.Write(payload); err != nil {
		return "", fmt.Errorf("server: audit feed collector request failed: %w", err)
	}
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		if err := closer.CloseWrite(); err != nil {
			return "", fmt.Errorf("server: audit feed collector request failed: %w", err)
		}
	}
	return "syslog:" + batch.BatchID, nil
}
