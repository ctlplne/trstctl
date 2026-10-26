// SPDX-License-Identifier: BUSL-1.1

package reconcile

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/reconcile/canon/reducers"
	"trstctl.com/trstctl/internal/reconcile/canon/reducers/kmip"
)

// kmipSourceTimeout bounds one observation, connection to last object.
const kmipSourceTimeout = 5 * time.Minute

// KMIPSourceConfig is one external KMIP server an authority observes (A124):
// KMIP 1.4 over TLS with a client certificate, reading object metadata with
// Locate and Get Attributes and certificate values with Get, never key values.
type KMIPSourceConfig struct {
	AuthorityID string
	// Address is the server's host:port (KMIP's registered port is 5696).
	Address string
	// ServerName is the name the server certificate must carry; empty means
	// the address host.
	ServerName     string
	CAFile         string
	ClientCertFile string
	ClientKeyFile  string
	// MaxObjects bounds one observation; zero means kmip.DefaultMaxObjects. A
	// server holding more fails the observation rather than yield a partial
	// inventory.
	MaxObjects int
	// AllowTLS12 accepts a server whose TLS stops at 1.2, with AEAD suites
	// only; the floor is otherwise TLS 1.3.
	AllowTLS12 bool
	// AllowLoopback permits a loopback address (lab, sidecar); TLS is still
	// required. PrivateEndpointCIDRs lets the SSRF-safe dialer reach a server
	// on an operator-owned private range.
	AllowLoopback        bool
	PrivateEndpointCIDRs []netip.Prefix
	// Dial overrides the network dial entirely (tests).
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
}

var errKMIPSourceConfig = errors.New("xrec kmip source: configuration")

type kmipSource struct {
	cfg  KMIPSourceConfig
	dial func(ctx context.Context, network, address string) (net.Conn, error)
}

var _ kmip.Source = (*kmipSource)(nil)

func newKMIPSource(cfg KMIPSourceConfig) (*kmipSource, error) {
	cfg.AuthorityID = strings.TrimSpace(cfg.AuthorityID)
	cfg.Address = strings.TrimSpace(cfg.Address)
	if cfg.AuthorityID == "" {
		return nil, fmt.Errorf("%w: authority id required", errKMIPSourceConfig)
	}
	host, port, err := net.SplitHostPort(cfg.Address)
	if n, convErr := strconv.Atoi(port); err != nil || host == "" || convErr != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("%w: address must be host:port", errKMIPSourceConfig)
	}
	if strings.TrimSpace(cfg.ServerName) == "" {
		cfg.ServerName = host
	}
	if strings.TrimSpace(cfg.CAFile) == "" || strings.TrimSpace(cfg.ClientCertFile) == "" || strings.TrimSpace(cfg.ClientKeyFile) == "" {
		return nil, fmt.Errorf("%w: ca_file, client_cert_file and client_key_file are required", errKMIPSourceConfig)
	}
	if cfg.MaxObjects < 0 {
		return nil, fmt.Errorf("%w: max_objects cannot be negative", errKMIPSourceConfig)
	}
	dial := cfg.Dial
	if dial == nil {
		opts := netsec.SafeClientOptions{AllowPrivateCIDRs: append([]netip.Prefix(nil), cfg.PrivateEndpointCIDRs...)}
		if cfg.AllowLoopback {
			opts.AllowPrivateCIDRs = append(opts.AllowPrivateCIDRs, netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128"))
		}
		dialer := &net.Dialer{Timeout: 30 * time.Second, Control: netsec.SafeDialControlWithOptions(opts)}
		dial = dialer.DialContext
	}
	return &kmipSource{cfg: cfg, dial: dial}, nil
}

// KMIPSnapshot implements kmip.Source: one connection per observation, every
// object the server shows this client, and objects whose type has no canon
// record skipped.
func (k *kmipSource) KMIPSnapshot(ctx context.Context, tenantID string, sb *reducers.ObservationSandbox) (kmip.Snapshot, error) {
	if sb == nil {
		sb = reducers.NewObservationSandbox(reducers.ReadOnlyObservationGrant(k.cfg.AuthorityID), nil)
	}
	ctx, cancel := context.WithTimeout(ctx, kmipSourceTimeout)
	defer cancel()
	raw, err := k.dial(ctx, "tcp", k.cfg.Address)
	if err != nil {
		return kmip.Snapshot{}, fmt.Errorf("xrec kmip source: dial %s: %w", k.cfg.Address, err)
	}
	var opts []mtls.RawClientOption
	if k.cfg.AllowTLS12 {
		opts = append(opts, mtls.AllowTLS12())
	}
	conn, err := mtls.MutualTLSClientConnFromFiles(ctx, raw, k.cfg.ClientCertFile, k.cfg.ClientKeyFile, k.cfg.CAFile, k.cfg.ServerName, opts...)
	if err != nil {
		return kmip.Snapshot{}, fmt.Errorf("xrec kmip source: %w", err)
	}
	defer func() { _ = conn.Close() }()

	now := time.Now().UTC()
	client := kmip.NewClient(k.cfg.AuthorityID, kmip.NewWireEndpoint(conn, k.cfg.MaxObjects))
	ids, err := client.Locate(ctx, sb, tenantID)
	if err != nil {
		return kmip.Snapshot{}, err
	}
	snap := kmip.Snapshot{Watermark: storeWatermark("kmip:"+k.cfg.AuthorityID, now)}
	for _, id := range ids {
		obj, err := client.GetAttributes(ctx, sb, id)
		if errors.Is(err, kmip.ErrUnmappedObjectType) {
			continue
		}
		if err != nil {
			return kmip.Snapshot{}, err
		}
		snap.Objects = append(snap.Objects, obj)
	}
	return snap, nil
}
