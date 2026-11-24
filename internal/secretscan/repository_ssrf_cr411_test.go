// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

type cr411Resolver struct {
	answers [][]net.IPAddr
	calls   int
}

func (r *cr411Resolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	index := r.calls
	r.calls++
	if index >= len(r.answers) {
		index = len(r.answers) - 1
	}
	return r.answers[index], nil
}

// A tenant controls clone_url. The worker must refuse a loopback target before
// Git opens a socket or sends a path and query to that target.
func TestCR411RepositoryCloneRefusesLoopbackBeforeConnecting(t *testing.T) {
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	_, err := PrepareRepositoryTarget(t.Context(), RepositoryScanConfig{
		Provider: "github", Repository: "tenant/repo", CloneURL: server.URL + "/internal.git?secret=probe",
	})
	if err == nil || hits.Load() != 0 {
		t.Fatalf("tenant clone reached loopback: hits=%d err=%v", hits.Load(), err)
	}
}

func TestCR411RepositoryCloneRefusesNonHTTPSBeforeGit(t *testing.T) {
	for _, target := range []string{"git://git.example.test/repo", "ssh://git.example.test/repo", "file:///tmp/repo", "../local-repo"} {
		t.Run(target, func(t *testing.T) {
			var runs int
			_, err := prepareRepositoryTargetWithGit(t.Context(), RepositoryScanConfig{
				Provider: "github", Repository: "tenant/repo", CloneURL: target,
			}, nil, func(context.Context, string, []string, ...string) error {
				runs++
				return nil
			})
			if err == nil || runs != 0 {
				t.Fatalf("non-HTTPS clone reached Git: %q runs=%d err=%v", strings.TrimSpace(target), runs, err)
			}
		})
	}
}

func TestCR411RepositoryClonePinsApprovedDNSAndRejectsMixedAnswers(t *testing.T) {
	public := net.IPAddr{IP: net.ParseIP("93.184.216.34")}
	private := net.IPAddr{IP: net.ParseIP("127.0.0.1")}
	const cloneURL = "https://git.example.test/team/repo.git"
	for _, tc := range []struct {
		name    string
		answers []net.IPAddr
		wantRun bool
	}{
		{"public pinned", []net.IPAddr{public}, true},
		{"mixed DNS refused", []net.IPAddr{public, private}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &cr411Resolver{answers: [][]net.IPAddr{tc.answers}}
			var runs int
			target, err := prepareRepositoryTargetWithGitEgress(t.Context(), RepositoryScanConfig{CloneURL: cloneURL}, nil,
				RepositoryCloneEgress{}, resolver, func(_ context.Context, _ string, config []string, args ...string) error {
					runs++
					if args[0] != "clone" || !gitConfigHas(config, "http.curloptResolve", "git.example.test:443:93.184.216.34") ||
						!gitConfigHas(config, "http.followRedirects", "false") || !gitConfigHas(config, "http.proxy", "") {
						t.Errorf("guarded Git config missing DNS pin, redirect refusal or proxy refusal: %v", config)
					}
					return nil
				})
			if tc.wantRun && (runs != 1 || err != nil) {
				t.Fatalf("approved clone: runs=%d err=%v", runs, err)
			}
			if err == nil {
				target.Cleanup()
			}
			if !tc.wantRun && (runs != 0 || !errors.Is(err, ErrRepositoryEgressBlocked)) {
				t.Fatalf("mixed DNS reached Git: runs=%d err=%v", runs, err)
			}
		})
	}
}

func TestCR411FollowupFetchRechecksDNSBeforeGit(t *testing.T) {
	resolver := &cr411Resolver{answers: [][]net.IPAddr{
		{{IP: net.ParseIP("93.184.216.34")}},
		{{IP: net.ParseIP("127.0.0.1")}},
	}}
	var clones, fetches int
	_, err := prepareRepositoryTargetWithGitEgress(t.Context(), RepositoryScanConfig{
		CloneURL: "https://git.example.test/team/repo.git", CommitSHA: "01234567",
	}, nil, RepositoryCloneEgress{}, resolver, func(_ context.Context, _ string, _ []string, args ...string) error {
		switch args[0] {
		case "clone":
			clones++
		case "fetch":
			fetches++
		case "checkout":
			return errors.New("fixture branch moved")
		}
		return nil
	})
	if clones != 1 || fetches != 0 || !errors.Is(err, ErrRepositoryEgressBlocked) {
		t.Fatalf("DNS changed before fetch: clones=%d fetches=%d err=%v", clones, fetches, err)
	}
}

func TestCR411PrivateCloneNeedsSourceAndOperatorCIDRs(t *testing.T) {
	policy, err := RepositoryCloneEgressFromCIDRs([]string{"127.0.0.1/32"}, []string{"127.0.0.0/8"})
	if err != nil || !policy.allows(netip.MustParseAddr("127.0.0.1")) {
		t.Fatalf("operator-approved exact loopback fixture refused: policy=%+v err=%v", policy, err)
	}
	for _, tc := range []struct{ requested, ceiling []string }{
		{[]string{"127.0.0.1/32"}, nil},
		{[]string{"10.0.0.0/8"}, []string{"10.2.0.0/16"}},
		{[]string{"0.0.0.0/0"}, []string{"10.0.0.0/8"}},
		{[]string{"0.0.0.0/1"}, []string{"0.0.0.0/1"}},
	} {
		if _, err := RepositoryCloneEgressFromCIDRs(tc.requested, tc.ceiling); !errors.Is(err, ErrRepositoryEgressBlocked) {
			t.Errorf("unsafe private CIDRs admitted: requested=%v ceiling=%v err=%v", tc.requested, tc.ceiling, err)
		}
	}
	metadata, err := RepositoryCloneEgressFromCIDRs([]string{"169.254.169.254/32"}, []string{"169.254.169.254/32"})
	if !errors.Is(err, ErrRepositoryEgressBlocked) || metadata.allows(netip.MustParseAddr("169.254.169.254")) {
		t.Fatalf("link-local metadata address reached under a grant: policy=%+v err=%v", metadata, err)
	}
	alias, err := RepositoryCloneEgressFromCIDRs([]string{"fd00:ec2::254/128"}, []string{"fd00:ec2::254/128"})
	if err != nil || alias.allows(netip.MustParseAddr("fd00:ec2::254")) {
		t.Fatalf("IPv6 metadata alias reached under a grant: policy=%+v err=%v", alias, err)
	}
}

func TestCR411GitChildCannotInheritProxyOrTransportOverrides(t *testing.T) {
	env := sanitizedGitEnv([]string{
		"PATH=/usr/bin", "HTTPS_PROXY=http://127.0.0.1:8080", "http_proxy=http://127.0.0.1:8080",
		"GIT_CONFIG_GLOBAL=/tmp/attacker-config", "GIT_CONFIG_PARAMETERS='url.ssh://host/.insteadOf=https://host/'",
		"GIT_SSL_NO_VERIFY=1", "GIT_SSL_CAINFO=/tmp/operator-ca.pem",
	})
	joined := strings.Join(env, "\n")
	for _, forbidden := range []string{"HTTPS_PROXY=", "http_proxy=", "GIT_CONFIG_PARAMETERS=", "GIT_SSL_NO_VERIFY=1", "attacker-config"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("Git inherited %s: %v", forbidden, env)
		}
	}
	for _, required := range []string{"GIT_ALLOW_PROTOCOL=https", "GIT_CONFIG_NOSYSTEM=1", "GIT_SSL_CAINFO=/tmp/operator-ca.pem"} {
		if !strings.Contains(joined, required) {
			t.Errorf("Git lost %s: %v", required, env)
		}
	}
}

func TestCR411CloneHostnameCannotInjectCurlResolveSyntax(t *testing.T) {
	for _, raw := range []string{
		"https://git.example,127.0.0.1/repo.git",
		"https://git..example/repo.git",
		"https://-git.example/repo.git",
		"https://[fe80::1%25en0]/repo.git",
	} {
		if err := ValidateRepositoryCloneURL(raw); !errors.Is(err, ErrRepositoryEgressBlocked) {
			t.Errorf("invalid Git/curl hostname admitted: %q, error=%v", raw, err)
		}
	}
}

func TestCR411IPv6LiteralKeepsCurlResolveFieldsSeparate(t *testing.T) {
	resolver := &cr411Resolver{answers: [][]net.IPAddr{{{IP: net.ParseIP("2001:4860:4860::8888")}}}}
	config, err := (RepositoryCloneEgress{}).gitConfig(t.Context(),
		"https://[2001:4860:4860::8888]/repo.git", resolver)
	if err != nil || !gitConfigHas(config, "http.curloptResolve", "[2001:4860:4860::8888]:443:[2001:4860:4860::8888]") {
		t.Fatalf("IPv6 literal was not bracketed for Git/curl pin: config=%v err=%v", config, err)
	}
}

func gitConfigHas(config []string, key, value string) bool {
	for i := 0; i+1 < len(config); i += 2 {
		if config[i] == key && config[i+1] == value {
			return true
		}
	}
	return false
}
