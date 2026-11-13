// SPDX-License-Identifier: BUSL-1.1

// Package scanannotate writes a leaked-secret finding back to the provider
// where the credential was seen (A174): a reply in the Slack thread, a
// comment on the Jira issue, a commit status on the CI run's commit at GitHub
// or GitLab, or an OCI referrer artifact on the container image. The note
// names the rule and the finding and asks for rotation; it never carries the
// secret or the matched text. Each write converges on retry: commit statuses
// and referrers are keyed by the finding, and a Slack reply or Jira comment
// is looked up by its marker before a retried write.
package scanannotate

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// Providers.
const (
	ProviderSlack    = "slack"
	ProviderJira     = "jira"
	ProviderGitHub   = "github"
	ProviderGitLab   = "gitlab"
	ProviderRegistry = "registry"
)

// Result statuses.
const (
	Confirmed      = "confirmed"
	AlreadyPresent = "already_present"
)

// Doer sends one HTTP request. *http.Client satisfies it.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Object is the provider-native place a finding was seen.
type Object struct {
	// Slack.
	Channel   string `json:"channel,omitempty"`
	ChannelID string `json:"channel_id,omitempty"`
	MessageTS string `json:"message_ts,omitempty"`
	ThreadTS  string `json:"thread_ts,omitempty"`
	// Jira.
	IssueKey string `json:"issue_key,omitempty"`
	// CI (GitHub "owner/repo" or a GitLab project ID or path).
	Repo      string `json:"repo,omitempty"`
	CommitSHA string `json:"commit_sha,omitempty"`
	// OCI registry.
	Repository string `json:"repository,omitempty"`
	Digest     string `json:"digest,omitempty"`
}

// Annotation is what the provider is told about one finding.
type Annotation struct {
	FindingID  string
	Rule       string
	Location   string
	DetectedAt string
	Object     Object
	// Retry reports that an earlier attempt may have reached the provider, so
	// a provider without a natural key looks for its marker first.
	Retry bool
	// EarlierOutcomeUnknown reports that an earlier attempt's write reached
	// the provider and its answer was lost (A174-L4). A retry that cannot
	// look for what it wrote then refuses rather than write a second time.
	EarlierOutcomeUnknown bool
}

// Result is what the provider confirmed.
type Result struct {
	Status      string
	ProviderRef string
	Detail      string
}

// Annotator writes one annotation at one provider.
type Annotator interface {
	Annotate(ctx context.Context, a Annotation) (Result, error)
}

// Connection is how to reach the provider.
type Connection struct {
	Provider string
	BaseURL  string
	Token    []byte
	// Username, when set, makes Jira use basic authentication (email and
	// API token) instead of a bearer personal access token.
	Username string
	Doer     Doer
}

// StatusError is a refusal the provider answered with.
type StatusError struct {
	Op   string
	Code int
	Body string
}

func (e *StatusError) Error() string {
	detail := strings.TrimSpace(e.Body)
	if len(detail) > 200 {
		detail = detail[:200]
	}
	if detail == "" {
		return fmt.Sprintf("%s: status %d", e.Op, e.Code)
	}
	return fmt.Sprintf("%s: status %d: %s", e.Op, e.Code, detail)
}

// ErrRetryable marks a refusal that may succeed later (Slack's ratelimited).
var ErrRetryable = errors.New("scanannotate: the provider asked to retry later")

// ErrOutcomeUnknown is a write whose request reached the provider but whose
// answer was lost (A174-L4): the provider may have acted. It stays
// retryable; the retry looks for what the earlier attempt wrote before
// writing again.
var ErrOutcomeUnknown = errors.New("scanannotate: the request reached the provider but its answer was lost")

// Retryable reports whether a failure may succeed if the row is delivered
// again: throttling, the provider's own failures, and the network.
func Retryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrRetryable) {
		return true
	}
	var refusal *RefusalError
	if errors.As(err, &refusal) {
		return false
	}
	var status *StatusError
	if errors.As(err, &status) {
		return status.Code == http.StatusTooManyRequests || status.Code >= 500
	}
	return !errors.Is(err, errInvalid)
}

var errInvalid = errors.New("scanannotate: invalid annotation")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errInvalid, fmt.Sprintf(format, args...))
}

// New builds the annotator for a connection. The returned close function
// wipes the token copy.
func New(c Connection) (Annotator, func(), error) {
	base := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if base == "" {
		return nil, nil, invalid("the annotation connection has no base_url")
	}
	if len(c.Token) == 0 {
		return nil, nil, invalid("the annotation connection has no token")
	}
	if c.Doer == nil {
		return nil, nil, invalid("the annotation connection has no HTTP client")
	}
	h := &httpClient{base: base, token: append([]byte(nil), c.Token...), username: strings.TrimSpace(c.Username), doer: c.Doer}
	closeFn := func() { secret.Wipe(h.token) }
	switch strings.ToLower(strings.TrimSpace(c.Provider)) {
	case ProviderSlack:
		return slack{h}, closeFn, nil
	case ProviderJira:
		return jira{h}, closeFn, nil
	case ProviderGitHub:
		return github{h}, closeFn, nil
	case ProviderGitLab:
		return gitlab{h}, closeFn, nil
	case ProviderRegistry:
		tokens := &registryTokens{byScope: map[string][]byte{}}
		return registry{h: h, tokens: tokens}, func() { tokens.wipe(); closeFn() }, nil
	default:
		closeFn()
		return nil, nil, invalid("no annotation provider %q", c.Provider)
	}
}

// Marker identifies a finding's note so a retried write can find it.
func Marker(findingID string) string { return "trstctl-finding:" + findingID }

// Message is the note's text: what was found, where, and what to do. It
// never contains the credential.
func Message(a Annotation, where string) string {
	return fmt.Sprintf("trstctl found a credential in this %s (rule %s, finding %s). Rotate the credential, then remove it from here. %s",
		where, a.Rule, shortID(a.FindingID), Marker(a.FindingID))
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
