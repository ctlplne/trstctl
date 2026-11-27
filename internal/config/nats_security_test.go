// SPDX-License-Identifier: BUSL-1.1

package config_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestC0012ExternalNATSRequiresTLSAndOutOfBandIdentity(t *testing.T) {
	base := config.Default()
	base.NATS.Mode = config.NATSExternal
	base.Signer.AllowCoResidentAuthorizer = false
	base.Signer.AuthTokenCommand = "/usr/local/bin/trstctl-sign-approve"
	base.NATS.URL = "nats://broker.example:4222"
	base.NATS.Replicas = 3
	base.NATS.NKeySeedFile = "/run/secrets/nats.seed"
	base.NATS.EventAuthKeyFile = "/run/secrets/event-auth.key"
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "tls://") {
		t.Fatalf("plaintext external NATS was accepted: %v", err)
	}
	base.NATS.URL = "tls://broker.example:4222"
	base.NATS.NKeySeedFile = ""
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "client identity") {
		t.Fatalf("credentialless external NATS was accepted: %v", err)
	}
	base.NATS.URL = "tls://user:password@broker.example:4222"
	base.NATS.NKeySeedFile = "/run/secrets/nats.seed"
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "URL credentials") {
		t.Fatalf("URL-embedded NATS credentials were accepted: %v", err)
	}
	base.NATS.URL = "tls://broker.example:4222"
	if err := base.Validate(); err != nil {
		t.Fatalf("TLS plus NKey seed file was refused: %v", err)
	}
	base.NATS.EventAuthKeyFile = ""
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "event_auth_key_file") {
		t.Fatalf("production external NATS without event authentication was accepted: %v", err)
	}
	base.NATS.EventAuthKeyFile = "/run/secrets/event-auth.key"
	base.NATS.URL = "nats://broker.example:4222"
	base.NATS.AllowPlaintextDev = true
	if err := base.Validate(); err != nil {
		t.Fatalf("explicit evaluation plaintext with NKey was refused: %v", err)
	}
}
