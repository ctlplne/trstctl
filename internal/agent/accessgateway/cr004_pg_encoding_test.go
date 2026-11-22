// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/accessrules"
	"trstctl.com/trstctl/internal/agent/relay"
)

type cr004ApprovingReviewer struct {
	sessionID, digest string
}

func (r cr004ApprovingReviewer) ReviewGatewayAction(_ context.Context, jobID int64, attempt int, key string, observation accessrules.Observation, _ bool) (accessrules.Decision, error) {
	observed := time.Now().UTC()
	deadline := observed.Add(30 * time.Second)
	return accessrules.Decision{ID: key, SessionID: r.sessionID, JobID: jobID, Attempt: attempt,
		Protocol: "postgres", Observation: observation, PolicyDigest: r.digest,
		Status: accessrules.StatusAuthorized, Reason: "review_approved", ObservedAt: observed,
		DecidedAt: observed.Add(time.Nanosecond), ReviewExpiresAt: &deadline}, nil
}

func TestCR004SQLSessionControlsNeverForwardEvenWithApproval(t *testing.T) {
	client, gatewayClient := net.Pipe()
	gatewayServer, backend := net.Pipe()
	defer func() { _ = client.Close(); _ = gatewayClient.Close(); _ = gatewayServer.Close(); _ = backend.Close() }()
	deadline := time.Now().Add(5 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = backend.SetDeadline(deadline)
	policy, digest := gatewayBlockPolicy(t, "postgres", []string{"SET"})
	sessionID := uuid.NewString()
	guard := &commandConnection{gateway: &Gateway{}, sessionID: sessionID, target: "pg-cr004", protocol: "postgres",
		connectionID: uuid.NewString(), policyDigest: digest, job: relay.Job{JobID: 41, Attempt: 1},
		policy: policy, reviewer: cr004ApprovingReviewer{sessionID: sessionID, digest: digest}, expiresAt: deadline}
	served := make(chan error, 1)
	go func() {
		served <- relayPostgresCommands(context.Background(), gatewayClient, gatewayServer, guard, nil)
	}()
	if _, err := client.Write(pgMessage('Q', []byte("SET client_encoding TO 'SJIS'\x00"))); err != nil {
		t.Fatal(err)
	}
	var header [5]byte
	_, err := io.ReadFull(backend, header[:])
	if err == nil {
		t.Fatalf("approved encoding control reached PostgreSQL as message %q", header[0])
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("backend read after refused control = %v, want closed connection", err)
	}
	if err := <-served; err == nil {
		t.Fatal("gateway accepted the unsafe encoding control")
	}
}

func TestCR004GuardedPostgresRefusesSJISStartupBeforeDial(t *testing.T) {
	client, gatewaySide := net.Pipe()
	defer func() { _ = client.Close(); _ = gatewaySide.Close() }()
	deadline := time.Now().Add(5 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = gatewaySide.SetDeadline(deadline)
	var dialed atomic.Bool
	served := make(chan error, 1)
	go func() {
		served <- servePostgres(context.Background(), gatewaySide, []byte("postgres://fixture:fixture@127.0.0.1:5432/app?sslmode=disable"),
			deadline, func(context.Context, string, string) (net.Conn, error) {
				dialed.Store(true)
				return nil, errors.New("test upstream must not be dialed")
			}, upstreamTrust{}, nil, &commandConnection{})
	}()
	start := binary.BigEndian.AppendUint32(nil, pgProtocol3)
	start = append(start, "user\x00fixture\x00database\x00app\x00client_encoding\x00SJIS\x00\x00"...)
	packet := binary.BigEndian.AppendUint32(nil, uint32(len(start)+4)) // #nosec G115 -- fixed test packet is well below the PostgreSQL wire length limit
	packet = append(packet, start...)
	if _, err := client.Write(packet); err != nil {
		t.Fatal(err)
	}
	var header [5]byte
	if _, err := io.ReadFull(client, header[:]); err != nil {
		t.Fatalf("gateway refusal header: %v", err)
	}
	length := binary.BigEndian.Uint32(header[1:])
	if header[0] != 'E' || length < 4 || length > 1024 {
		t.Fatalf("guarded startup response = %x", header)
	}
	message := make([]byte, length-4)
	if _, err := io.ReadFull(client, message); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if err := <-served; err == nil {
		t.Error("SJIS startup unexpectedly completed")
	}
	if dialed.Load() || !bytes.Contains(message, []byte("UTF8")) || !strings.Contains(string(message), "command rules") {
		t.Errorf("SJIS startup dialed=%v, refusal=%q; want a UTF8 guard before upstream dial", dialed.Load(), message)
	}
}

func TestCR004GuardedPostgresClosesOnBackendEncodingChange(t *testing.T) {
	client, gatewayClient := net.Pipe()
	gatewayServer, backend := net.Pipe()
	defer func() { _ = client.Close(); _ = gatewayClient.Close(); _ = gatewayServer.Close(); _ = backend.Close() }()
	deadline := time.Now().Add(5 * time.Second)
	_ = client.SetDeadline(deadline)
	_ = backend.SetDeadline(deadline)
	served := make(chan error, 1)
	go func() {
		served <- relayPostgresCommands(context.Background(), gatewayClient, gatewayServer, &commandConnection{}, nil)
	}()
	if _, err := backend.Write(pgMessage('S', []byte("client_encoding\x00SJIS\x00"))); err != nil {
		t.Fatal(err)
	}
	var header [5]byte
	if _, err := io.ReadFull(client, header[:]); err != nil {
		t.Fatalf("gateway status refusal: %v", err)
	}
	if header[0] != 'E' {
		t.Fatalf("guarded gateway forwarded backend non-UTF8 ParameterStatus %q", header[0])
	}
	length := binary.BigEndian.Uint32(header[1:])
	if length < 4 || length > 1024 {
		t.Fatalf("invalid PostgreSQL refusal length %d", length)
	}
	message := make([]byte, length-4)
	if _, err := io.ReadFull(client, message); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(message, []byte("encoding")) {
		t.Errorf("refusal %q does not explain the changed encoding", message)
	}
	_ = client.Close()
	if err := <-served; err == nil {
		t.Error("relay accepted a backend switch to SJIS")
	}
}

func TestCR004GuardedPostgresRequiresServerUTF8Status(t *testing.T) {
	for _, tc := range []struct {
		name   string
		params [][2]string
		want   bool
	}{
		{"UTF8", [][2]string{{"client_encoding", "UTF8"}}, true},
		{"missing", [][2]string{{"server_version", "16.15"}}, false},
		{"SJIS", [][2]string{{"client_encoding", "SJIS"}}, false},
		{"contradictory", [][2]string{{"client_encoding", "SJIS"}, {"client_encoding", "UTF8"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := postgresParametersUTF8(tc.params); got != tc.want {
				t.Errorf("server statuses %v accepted=%v, want %v", tc.params, got, tc.want)
			}
		})
	}
}
