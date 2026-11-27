// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/eventstest"
)

func TestC0012EvaluationBrokerRequiresProvisionedNKey(t *testing.T) {
	dir := t.TempDir()
	seedPath, configPath := filepath.Join(dir, "nats.seed"), filepath.Join(dir, "nats.conf")
	authPath := filepath.Join(dir, "event-auth.key")
	if err := runNATSKey([]string{"provision", seedPath, configPath}, io.Discard); err != nil {
		t.Fatal(err)
	}
	firstSeed, err := os.ReadFile(seedPath) // #nosec G304 -- read the test-owned secret path to prove restart stability (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(firstSeed)
	firstAuth, err := os.ReadFile(authPath) // #nosec G304 -- task-owned event MAC fixture (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(firstAuth)
	if err := runNATSKey([]string{"provision", seedPath, configPath}, io.Discard); err != nil {
		t.Fatalf("repeated setup changed the evaluation identity: %v", err)
	}
	again, err := os.ReadFile(seedPath) // #nosec G304 -- read the same test-owned secret path (CWE-22)
	defer secret.Wipe(again)
	if err != nil || !bytes.Equal(firstSeed, again) {
		t.Fatalf("NATS identity changed on restart: %v", err)
	}
	againAuth, err := os.ReadFile(authPath) // #nosec G304 -- task-owned event MAC fixture (CWE-22)
	if err != nil || !bytes.Equal(firstAuth, againAuth) {
		t.Fatalf("event authentication key changed on restart: %v", err)
	}
	defer secret.Wipe(againAuth)
	options, err := natsserver.ProcessConfigFile(configPath)
	if err != nil {
		t.Fatalf("generated NATS authorization config: %v", err)
	}
	options.JetStream, options.StoreDir, options.Port = true, filepath.Join(dir, "store"), -1
	srv, err := natsserver.NewServer(options)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		t.Fatal("authenticated evaluation broker did not start")
	}
	t.Cleanup(srv.Shutdown)
	if attacker, err := nats.Connect(srv.ClientURL(), nats.NoReconnect()); err == nil {
		attacker.Close()
		t.Fatal("anonymous peer connected to the shipped broker configuration")
	}
	log, err := eventstest.OpenFixture(t.Context(), config.NATS{
		Mode: config.NATSExternal, URL: srv.ClientURL(), Replicas: 1,
		AllowSingleReplica: true, AllowPlaintextDev: true, NKeySeedFile: seedPath,
		EventAuthKeyFile: authPath,
	})
	if err != nil {
		t.Fatalf("NKey-authenticated control plane could not connect: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	if err := log.Ping(t.Context()); err != nil {
		t.Fatal(err)
	}
}
