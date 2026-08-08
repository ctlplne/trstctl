// SPDX-License-Identifier: MPL-2.0

package fleet

import (
	"strings"
	"testing"
)

const okDigest = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"

func TestValidateArtifactsRefusalsNameTheField(t *testing.T) {
	cases := []struct {
		name string
		in   []Artifact
		want string
	}{
		{"missing platform", []Artifact{{URL: "https://x.example/a", SHA256: okDigest}}, "os and arch"},
		{"duplicate platform", []Artifact{
			{OS: "linux", Arch: "amd64", URL: "https://x.example/a", SHA256: okDigest},
			{OS: "Linux", Arch: "AMD64", URL: "https://x.example/b", SHA256: okDigest},
		}, "listed twice"},
		{"relative url", []Artifact{{OS: "linux", Arch: "amd64", URL: "/a", SHA256: okDigest}}, "absolute http(s)"},
		{"short digest", []Artifact{{OS: "linux", Arch: "amd64", URL: "https://x.example/a", SHA256: "abc123"}}, "64 hex"},
		{"non-hex digest", []Artifact{{OS: "linux", Arch: "amd64", URL: "https://x.example/a",
			SHA256: strings.Repeat("z", 64)}}, "64 hex"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateArtifacts(tc.in)
			if err == nil {
				t.Fatalf("accepted %v; a campaign built on this either dispatches nothing or "+
					"cannot pin what the fleet installs", tc.in)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal %q does not name the problem (%q); an operator hits this at "+
					"campaign start and the message is the fix", err, tc.want)
			}
		})
	}
	if err := ValidateArtifacts([]Artifact{
		{OS: "linux", Arch: "amd64", URL: "https://dl.example/agent", SHA256: okDigest},
		{OS: "windows", Arch: "amd64", URL: "https://dl.example/agent.exe", SHA256: okDigest},
	}); err != nil {
		t.Fatalf("refused a valid list: %v", err)
	}
	if err := ValidateArtifacts(nil); err != nil {
		t.Fatalf("refused the empty list: %v — empty means observe-only, which is a valid campaign", err)
	}
}

func TestArtifactForMatchesPlatformCaseInsensitively(t *testing.T) {
	list := []Artifact{
		{OS: "Linux", Arch: "AMD64", URL: "https://dl.example/linux", SHA256: okDigest},
		{OS: "windows", Arch: "arm64", URL: "https://dl.example/win", SHA256: okDigest},
	}
	got, ok := ArtifactFor(list, "linux", "amd64")
	if !ok || got.URL != "https://dl.example/linux" {
		t.Fatalf("ArtifactFor(linux/amd64) = %+v, %v", got, ok)
	}
	if _, ok := ArtifactFor(list, "darwin", "arm64"); ok {
		t.Fatal("matched a platform nobody published; the agent would install the wrong OS's binary")
	}
}

func TestEncodeArtifactsNilStaysNil(t *testing.T) {
	raw, err := EncodeArtifacts(nil)
	if err != nil || raw != nil {
		t.Fatalf("EncodeArtifacts(nil) = %q, %v; an observe-only campaign must store NULL, not \"[]\" — "+
			"the column is how the sweep decides whether to dispatch", raw, err)
	}
	round, err := DecodeArtifacts(nil)
	if err != nil || round != nil {
		t.Fatalf("DecodeArtifacts(nil) = %v, %v", round, err)
	}
}
