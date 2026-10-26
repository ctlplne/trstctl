// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"fmt"
	"strings"
	"sync/atomic"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/native"
	connectorwasm "trstctl.com/trstctl/internal/connector/wasm/host"
)

// connectorsInProcess makes this agent run the shipped families as trusted
// in-process code instead of in the WASM connector sandbox. The agent sets it
// from --connector-isolation before it claims any job.
var connectorsInProcess atomic.Bool

// SetConnectorsInProcess chooses how this agent runs the shipped connector
// families: false (the default) runs every operation in a fresh instance of
// the embedded connector module, true runs them in this process.
func SetConnectorsInProcess(inProcess bool) { connectorsInProcess.Store(inProcess) }

// ConnectorIsolation reports how this agent runs the shipped families.
func ConnectorIsolation() string {
	if connectorsInProcess.Load() {
		return connector.IsolationInProcess
	}
	return connector.IsolationWASMSandbox
}

// buildShipped constructs family through the constructor census the control
// plane uses — same constructors, same options — reading each credential from
// the material redeemed for this attempt, and binds it into the WASM connector
// sandbox unless the agent runs connectors in process.
func buildShipped(family string, target native.Target, material Material) (connector.Connector, error) {
	credentials := map[string][]byte{}
	built, destroy, err := native.Build(family, target, func(ref, _ string) ([]byte, error) {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return nil, fmt.Errorf("relay: the %s target names no reference", family)
		}
		value, ok := material[ref]
		if !ok || len(value) == 0 {
			return nil, fmt.Errorf("relay: it was not redeemed for this attempt")
		}
		credentials[ref] = value
		return value, nil
	})
	if err != nil {
		return nil, err
	}
	if connectorsInProcess.Load() {
		return built, nil
	}
	rt, err := connectorwasm.Builtin()
	if err != nil {
		closeBuilt(built, destroy)
		return nil, fmt.Errorf("relay: the connector sandbox is unavailable (run the agent with --connector-isolation=%s to run connectors in process): %w", connector.IsolationInProcess, err)
	}
	bound, err := rt.Bind(built, family, target, credentials)
	if err != nil {
		closeBuilt(built, destroy)
		return nil, err
	}
	// The host-built instance only names the family, declares its grant and
	// releases what it owns; it never runs an operation, so the token copies
	// its cloud credential providers hold can go now.
	for _, d := range destroy {
		d.Destroy()
	}
	return bound, nil
}

func closeBuilt(built connector.Connector, destroy []interface{ Destroy() }) {
	for _, d := range destroy {
		d.Destroy()
	}
	if closer, ok := built.(interface{ Close() }); ok {
		closer.Close()
	}
}

// relayTarget maps a relay target's routing fields onto the census schema.
func relayTarget(t TargetConfig) native.Target {
	return native.Target{
		Endpoint: t.Endpoint, Username: t.Username, PasswordRef: t.PasswordRef, TokenRef: t.TokenRef,
		APIKeyRef: t.APIKeyRef, ObjectName: t.ObjectName, ClientSSLProfile: t.ClientSSLProfile,
		FileLocation: t.FileLocation, SecretName: t.SecretName, BindTo: t.BindTo,
		SSLTLSProfile: t.SSLTLSProfile, CommitAdmin: t.CommitAdmin,
		NodeHostname: t.NodeHostname, CertificateRoles: append([]string(nil), t.CertificateRoles...),
		PeerEndpoint: t.PeerEndpoint, PeerObjectName: t.PeerObjectName,
		Region: t.Region, AccessKeyID: t.AccessKeyID, SecretAccessKeyRef: t.SecretAccessKeyRef,
		SessionTokenRef: t.SessionTokenRef, BearerTokenRef: t.BearerTokenRef, APIVersion: t.APIVersion,
		Project: t.Project, Location: t.Location, PollInterval: t.PollInterval,
		CertificateMapEntry: t.CertificateMapEntry, Vantage: t.Vantage,
	}
}

// hostTarget maps a host target's fields onto the census schema.
func hostTarget(t HostTargetConfig) native.Target {
	return native.Target{
		CertPath: t.CertPath, KeyPath: t.KeyPath, CRTPath: t.CRTPath, ConfigPath: t.ConfigPath,
		Endpoint: t.Endpoint, SecretName: t.SecretName,
		Binding: t.Binding, Store: t.Store, AppID: t.AppID, ImportDir: t.ImportDir,
		PostfixCertPath: t.PostfixCertPath, PostfixKeyPath: t.PostfixKeyPath,
		DovecotCertPath: t.DovecotCertPath, DovecotKeyPath: t.DovecotKeyPath,
		KeystorePath: t.KeystorePath, KeystorePasswordRef: t.KeystorePasswordRef, Alias: t.Alias,
		Format: t.Format, ReloadAction: t.ReloadAction,
	}
}
