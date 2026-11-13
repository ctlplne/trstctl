// SPDX-License-Identifier: BUSL-1.1

package scanannotate

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// A174-L5: a first-party repository scan's finding is annotated through
// GitHub code scanning. The finding is uploaded as a SARIF analysis of its
// own (one category per finding, so each alert stands alone) naming the
// rule, the file and the line, never the secret. GitHub keeps the latest
// analysis per category, so a retried upload replaces the same one, and
// resolving the finding uploads its category with no result, which closes
// the alert.

// ObjectKindRepositoryFile is a file in a repository at a commit: where a
// first-party repository scan saw a credential.
const ObjectKindRepositoryFile = "repository_file"

// CodeScanningCategory is the analysis category a finding is uploaded under.
func CodeScanningCategory(findingID string) string { return "trstctl/leaked-secret/" + findingID }

// leakedSecretSARIF is the finding as a SARIF 2.1.0 log, gzipped and base64
// encoded the way the code scanning upload takes it; resolved leaves out the
// result.
func leakedSecretSARIF(a Annotation, resolved bool) (string, error) {
	line, err := strconv.Atoi(strings.TrimSpace(a.Object.Line))
	if err != nil || line < 1 {
		line = 1
	}
	results := []any{}
	if !resolved {
		results = append(results, map[string]any{
			"ruleId":  a.Rule,
			"level":   "error",
			"message": map[string]any{"text": Message(a, "file")},
			"locations": []any{map[string]any{"physicalLocation": map[string]any{
				"artifactLocation": map[string]any{"uri": a.Object.Path},
				"region":           map[string]any{"startLine": line},
			}}},
			"partialFingerprints": map[string]string{"trstctlFinding/v1": a.FindingID},
		})
	}
	raw, err := json.Marshal(map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{"name": "trstctl", "informationUri": "https://trstctl.com",
				"rules": []any{map[string]any{"id": a.Rule, "shortDescription": map[string]string{"text": "Leaked credential (" + a.Rule + ")"},
					"properties": map[string]any{"tags": []string{"security", "secret"}, "security-severity": "9.0"}}}}},
			"automationDetails": map[string]string{"id": CodeScanningCategory(a.FindingID) + "/"},
			"results":           results,
		}},
	})
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// uploadCodeScanning uploads the finding's analysis (or, resolved, its empty
// one) to GitHub code scanning.
func (g github) uploadCodeScanning(ctx context.Context, a Annotation, resolved bool) (Result, error) {
	repo, sha, ref := strings.Trim(strings.TrimSpace(a.Object.Repo), "/"), strings.TrimSpace(a.Object.CommitSHA), strings.TrimSpace(a.Object.Ref)
	parts := strings.Split(repo, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || sha == "" || !strings.HasPrefix(ref, "refs/") || strings.TrimSpace(a.Object.Path) == "" {
		return Result{}, invalid("a code scanning upload needs repo (owner/name), commit_sha, ref (refs/...) and the file's path")
	}
	sarif, err := leakedSecretSARIF(a, resolved)
	if err != nil {
		return Result{}, err
	}
	var resp struct {
		ID string `json:"id"`
	}
	if _, _, err := g.h.do(ctx, request{op: "github code scanning upload", method: http.MethodPost,
		path:        "/repos/" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1]) + "/code-scanning/sarifs",
		body:        jsonBody(map[string]string{"commit_sha": sha, "ref": ref, "sarif": sarif, "tool_name": "trstctl"}),
		contentType: "application/json", auth: func(req *http.Request) {
			g.h.bearer(req)
			req.Header.Set("Accept", "application/vnd.github+json")
			req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		}, out: &resp}); err != nil {
		return Result{}, err
	}
	where := a.Object.Path + ":" + strings.TrimSpace(a.Object.Line)
	if resolved {
		return Result{Status: Resolved, ProviderRef: "code-scanning:" + resp.ID,
			Detail: "GitHub code scanning took analysis " + resp.ID + " of " + CodeScanningCategory(a.FindingID) + " with no result: the alert at " + where + " closes"}, nil
	}
	return Result{Status: Confirmed, ProviderRef: "code-scanning:" + resp.ID,
		Detail: "GitHub code scanning took analysis " + resp.ID + " (" + CodeScanningCategory(a.FindingID) + ") for " + where + " on " + sha}, nil
}
