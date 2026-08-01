// SPDX-License-Identifier: MPL-2.0

package events

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/privacyref"
)

func TestPseudonymizeDataBytesRewritesEscapedJSONStringsWithoutReformatting(t *testing.T) {
	subject := "alice\"\\\n☃😀"
	const placeholder = "subject-ref:erased"
	input := []byte("{\n" +
		"  \"untouched\\u004bey\" : \"raw\\u003ctag\", \n" +
		"  \"target\" : \"before alice\\u0022\\u005c\\u000a\\u2603\\ud83d\\ude00 after\\u004b\\/\\u003c\",\n" +
		"  \"array\": [ \"alice\\\"\\\\\\n☃😀\", \"keep\\u00e9\" ],\n" +
		"  \"alice\\u0022\\u005c\\u000a\\u2603\\ud83d\\ude00\" : \"key-remains\"\n" +
		"}")
	want := []byte("{\n" +
		"  \"untouched\\u004bey\" : \"raw\\u003ctag\", \n" +
		"  \"target\" : \"before subject-ref:erased after\\u004b\\/\\u003c\",\n" +
		"  \"array\": [ \"subject-ref:erased\", \"keep\\u00e9\" ],\n" +
		"  \"subject-ref:erased\" : \"key-remains\"\n" +
		"}")

	got, changed := pseudonymizeDataBytes(input, subject, placeholder)
	if !changed {
		t.Fatal("pseudonymizeDataBytes reported no change for escaped semantic values")
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("escaped JSON rewrite changed an unrelated raw span:\n got=%q\nwant=%q", got, want)
	}
}

func TestPseudonymizeDataBytesRewritesEscapedJSONObjectKey(t *testing.T) {
	input := []byte(`{ "owner\u0040example.com" : "keep\u003craw" }`)
	want := []byte(`{ "subject-ref:erased" : "keep\u003craw" }`)

	got, changed := pseudonymizeDataBytes(input, "owner@example.com", "subject-ref:erased")
	if !changed {
		t.Fatal("pseudonymizeDataBytes reported no change for escaped object key")
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("escaped object-key rewrite = %q, want exact span-preserving result %q", got, want)
	}
}

func TestPseudonymizeDataBytesInvalidJSONUsesRawFallback(t *testing.T) {
	input := []byte(`prefix alice@example.com {"escaped":"alice\u0040example.com"`)
	want := []byte(`prefix subject-ref:erased {"escaped":"alice\u0040example.com"`)

	got, changed := pseudonymizeDataBytes(input, "alice@example.com", "subject-ref:erased")
	if !changed {
		t.Fatal("pseudonymizeDataBytes reported no change for raw non-JSON subject")
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("invalid JSON fallback = %q, want exact raw replacement %q", got, want)
	}
}

func TestSubjectErasurePseudonymizeSubjectSecureRewritesHotLogStorage(t *testing.T) {
	ctx := context.Background()
	const (
		tenantID = "11111111-1111-1111-1111-111111111111"
		subject  = "alice@example.com"
	)
	originalData := []byte("{\n  \"z\": \"keep\\\\u003cbytes\", \"name\" : \"alice@example.com\",\n  \"nested\": [ \"keep\", \"alice@example.com\" ]\n}")
	log, err := openRewriteLog(t, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })

	actorCtx := ContextWithActor(ctx, Actor{Subject: subject, Roles: []string{"admin"}})
	if _, err := log.Append(actorCtx, Event{
		Type:     "owner.created",
		TenantID: tenantID,
		Data:     originalData,
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if raw := rawStreamBytes(t, log); !bytes.Contains(raw, []byte(subject)) {
		t.Fatalf("expected raw hot-log storage to contain the subject before erasure, got %s", raw)
	}

	if err := log.PseudonymizeSubject(ctx, tenantID, subject, rewriteProofOptions(t)...); err != nil {
		t.Fatalf("PseudonymizeSubject: %v", err)
	}
	raw := rawStreamBytes(t, log)
	if bytes.Contains(raw, []byte(subject)) {
		t.Fatalf("hot-log storage still contains erased subject bytes: %s", raw)
	}
	placeholder := privacyref.Placeholder(privacyref.SubjectRef(tenantID, subject))
	if !bytes.Contains(raw, []byte(placeholder)) {
		t.Fatalf("hot-log storage = %s, want erasure placeholder %q", raw, placeholder)
	}

	var got []Event
	if err := log.Replay(ctx, 0, func(e Event) error {
		got = append(got, e)
		return nil
	}); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("replayed %d events, want sanitized event plus continuity receipt", len(got))
	}
	if got[0].Actor == nil || got[0].Actor.Subject != placeholder {
		t.Fatalf("replayed actor = %+v, want placeholder %q", got[0].Actor, placeholder)
	}
	if bytes.Contains(got[0].Data, []byte(subject)) || !bytes.Contains(got[0].Data, []byte(placeholder)) {
		t.Fatalf("replayed data = %s, want placeholder and no raw subject", got[0].Data)
	}
	if want := bytes.ReplaceAll(originalData, []byte(subject), []byte(placeholder)); !bytes.Equal(got[0].Data, want) {
		t.Fatalf("pseudonymized payload changed unrelated bytes:\n got=%q\nwant=%q", got[0].Data, want)
	}
	if got[1].Type != "tenant.data.rewrite.receipt" {
		t.Fatalf("replayed second event type = %q, want continuity receipt", got[1].Type)
	}
}

func TestSubjectErasureNoOpKeepsGenerationSequenceAndMetadata(t *testing.T) {
	ctx := context.Background()
	const tenantID = "11111111-1111-1111-1111-111111111111"
	log, err := openRewriteLog(t, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	event, err := log.Append(ctx, Event{
		Type: "owner.created", TenantID: tenantID, Data: []byte(`{"subject":"bob@example.com"}`),
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	beforeName, _, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatalf("resolve before no-op: %v", err)
	}

	if err := log.PseudonymizeSubject(ctx, tenantID, "alice@example.com", rewriteProofOptions(t)...); err != nil {
		t.Fatalf("PseudonymizeSubject no-op: %v", err)
	}
	afterName, stream, err := log.resolveActiveStream(ctx)
	if err != nil {
		t.Fatalf("resolve after no-op: %v", err)
	}
	if afterName != beforeName {
		t.Fatalf("no-op switched generation from %q to %q", beforeName, afterName)
	}
	info, err := log.infoForStream(ctx, stream)
	if err != nil {
		t.Fatalf("stream info: %v", err)
	}
	if info.State.LastSeq != event.Sequence {
		t.Fatalf("no-op consumed sequence: head=%d want=%d", info.State.LastSeq, event.Sequence)
	}
	for key := range info.Config.Metadata {
		if strings.HasPrefix(key, "trstctl.rewrite.") {
			t.Fatalf("no-op left rewrite metadata %q", key)
		}
	}
}

func TestSubjectErasurePseudonymizeSubjectFailsClosedWithoutProofCallbacks(t *testing.T) {
	ctx := context.Background()
	const (
		tenantID = "11111111-1111-1111-1111-111111111111"
		subject  = "alice@example.com"
	)
	log, err := openRewriteLog(t, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	if _, err := log.Append(ctx, Event{
		Type: "owner.created", TenantID: tenantID,
		Data: []byte(`{"subject":"alice@example.com"}`),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	before := rawStreamBytes(t, log)

	if err := log.PseudonymizeSubject(ctx, tenantID, subject); err == nil {
		t.Fatal("PseudonymizeSubject accepted missing continuity proof callbacks")
	}
	if after := rawStreamBytes(t, log); !bytes.Equal(after, before) {
		t.Fatalf("hot log changed despite fail-closed proof wall:\nbefore=%s\nafter=%s", before, after)
	}
}

func TestPseudonymizeSubjectCompletionStaysInsideRewriteOperationLock(t *testing.T) {
	ctx := context.Background()
	const (
		tenantID = "11111111-1111-1111-1111-111111111111"
		subject  = "alice@example.com"
	)
	log, err := openRewriteLog(t, config.NATS{
		Mode: config.NATSEmbedded, StoreDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Open embedded: %v", err)
	}
	defer func() { _ = log.Close() }()
	if _, err := log.Append(ctx, Event{
		ID: "completion-source", Type: "owner.created", TenantID: tenantID,
		Data: []byte(`{"subject":"alice@example.com"}`),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	competingEntered := make(chan struct{})
	competingDone := make(chan error, 1)
	var completionCalls int
	err = log.PseudonymizeSubjectWithCompletion(
		ctx,
		tenantID,
		subject,
		func(completionCtx context.Context) error {
			completionCalls++
			go func() { // #nosec G118 -- test goroutine lifecycle is managed by the test (CWE-664)
				competingDone <- log.WithHistoryOperation(
					context.Background(),
					func(context.Context) error {
						close(competingEntered)
						return nil
					},
				)
			}()
			select {
			case <-competingEntered:
				return errors.New("competing history operation entered before completion returned")
			case <-time.After(50 * time.Millisecond):
			}
			_, err := log.Append(completionCtx, Event{
				ID: "privacy-completion", Type: "privacy.subject.erased",
				TenantID: tenantID, Data: []byte(`{"completed":true}`),
			})
			return err
		},
		rewriteProofOptions(t)...,
	)
	if err != nil {
		t.Fatalf("PseudonymizeSubjectWithCompletion: %v", err)
	}
	if completionCalls != 1 {
		t.Fatalf("completion calls = %d, want 1", completionCalls)
	}
	select {
	case err := <-competingDone:
		if err != nil {
			t.Fatalf("competing history operation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("competing history operation did not enter after completion released lock")
	}
}

func rawStreamBytes(t *testing.T, log *Log) []byte {
	t.Helper()
	info, err := log.streamInfo(context.Background())
	if err != nil {
		t.Fatalf("streamInfo: %v", err)
	}
	var out []byte
	for seq := uint64(1); seq <= info.State.LastSeq; seq++ {
		msg, err := log.stream.GetMsg(context.Background(), seq)
		if err != nil {
			if errors.Is(err, jetstream.ErrMsgNotFound) {
				continue
			}
			t.Fatalf("GetMsg(%d): %v", seq, err)
		}
		out = append(out, msg.Data...)
	}
	return out
}
