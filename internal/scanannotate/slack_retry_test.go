// SPDX-License-Identifier: BUSL-1.1

package scanannotate_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/scanannotate"
	"trstctl.com/trstctl/internal/scanannotate/scanannotatetest"
)

// A174-L4: a Slack reply is never posted twice. A post whose answer is lost
// after its request reached Slack is an unknown outcome (retryable); a retry
// that can read the thread finds the reply; one that cannot read it posts
// again only when the earlier attempt never reached Slack, and otherwise
// refuses, naming the scope that would let it check.
func TestSlackRetryNeverPostsTwiceA174L4(t *testing.T) {
	stand := scanannotatetest.New(a174Token, "")
	t.Cleanup(stand.Close)
	ctx := context.Background()
	slack := annotator(t, stand, "slack", "")
	for _, ts := range []string{"4.1", "4.2", "4.3"} {
		stand.SeedSlackMessage("C0L4", ts)
	}
	post := func(id, ts string, retry, unknown bool) (scanannotate.Result, error) {
		return slack.Annotate(ctx, scanannotate.Annotation{FindingID: id, Rule: "slack-bot-token",
			Object: scanannotate.Object{ChannelID: "C0L4", MessageTS: ts}, Retry: retry, EarlierOutcomeUnknown: unknown})
	}
	replies := func(ts string) int { return len(stand.SlackReplies("C0L4", ts)) }

	// The answer is lost: the reply landed, the outcome is unknown.
	stand.SlackLoseNextAnswers(1)
	if _, err := post("f1740004-0000-4000-8000-000000000001", "4.1", false, false); !errors.Is(err, scanannotate.ErrOutcomeUnknown) || !scanannotate.Retryable(err) {
		t.Fatalf("lost answer = %v; want a retryable unknown outcome", err)
	}
	if replies("4.1") != 1 {
		t.Fatalf("replies = %d", replies("4.1"))
	}
	// A token that can read the thread finds it.
	if got, err := post("f1740004-0000-4000-8000-000000000001", "4.1", true, true); err != nil || got.Status != scanannotate.AlreadyPresent || replies("4.1") != 1 {
		t.Fatalf("retry that can read = %+v %v (%d replies)", got, err, replies("4.1"))
	}

	// One that cannot read it refuses rather than post a second reply.
	stand.SlackRefuseReads("missing_scope")
	stand.SlackLoseNextAnswers(1)
	if _, err := post("f1740004-0000-4000-8000-000000000002", "4.2", false, false); !errors.Is(err, scanannotate.ErrOutcomeUnknown) {
		t.Fatalf("lost answer = %v", err)
	}
	_, err := post("f1740004-0000-4000-8000-000000000002", "4.2", true, true)
	if err == nil || scanannotate.Retryable(err) || !strings.Contains(err.Error(), "missing_scope") || !strings.Contains(err.Error(), "channels:history") {
		t.Fatalf("retry that cannot read after an unknown outcome = %v; want a final refusal naming the scope", err)
	}
	if replies("4.2") != 1 {
		t.Fatalf("the thread has %d replies; want the one that landed", replies("4.2"))
	}

	// An earlier attempt that never reached Slack is retried even unread.
	stand.SlackLimitNext(1)
	if _, err := post("f1740004-0000-4000-8000-000000000003", "4.3", false, false); err == nil || errors.Is(err, scanannotate.ErrOutcomeUnknown) {
		t.Fatalf("ratelimited = %v; want a retryable known outcome", err)
	}
	if got, err := post("f1740004-0000-4000-8000-000000000003", "4.3", true, false); err != nil || got.Status != scanannotate.Confirmed || replies("4.3") != 1 {
		t.Fatalf("retry after a known outcome = %+v %v (%d replies)", got, err, replies("4.3"))
	}

	// A connection that is never made is no unknown outcome.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "http://" + listener.Addr().String()
	_ = listener.Close()
	offline, closeFn, err := scanannotate.New(scanannotate.Connection{Provider: "slack", BaseURL: closed, Token: []byte(a174Token), Doer: http.DefaultClient})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeFn)
	_, err = offline.Annotate(ctx, scanannotate.Annotation{FindingID: "f1740004-0000-4000-8000-000000000004", Rule: "r",
		Object: scanannotate.Object{ChannelID: "C0L4", MessageTS: "4.4"}})
	if err == nil || errors.Is(err, scanannotate.ErrOutcomeUnknown) || !scanannotate.Retryable(err) {
		t.Fatalf("unreachable Slack = %v; want a retryable failure that never reached it", err)
	}
}
