// SPDX-License-Identifier: BUSL-1.1

package scancollect

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/secrettext"
)

// CI systems a cicd_log collection reads.
const (
	SystemGitHub = "github"
	SystemGitLab = "gitlab"
)

const maxLogArchiveBytes = 256 << 20

var (
	githubRepo   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)
	gitlabRepo   = regexp.MustCompile(`^(?:[0-9]{1,12}|[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+){1,20})$`)
	commitSHA    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	ciFolderPart = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)
)

// ciFolder is the collection folder of one CI run or job; ObjectForPath reads
// the object back from it: ci/<system>/<repo with / as __>/<commit>/<run or job>/.
func ciFolder(system, repo, commit, id string) string {
	return "ci/" + system + "/" + strings.ReplaceAll(repo, "/", "__") + "/" + commit + "/" + id + "/"
}

// ObjectForPath is the provider object of a file in a CI log collection: the
// system, repository, commit and run or job, as an annotation names it.
func ObjectForPath(file string) (map[string]string, bool) {
	parts := strings.Split(path.Clean(strings.ReplaceAll(file, "\\", "/")), "/")
	if len(parts) < 6 || parts[0] != "ci" || (parts[1] != SystemGitHub && parts[1] != SystemGitLab) || !commitSHA.MatchString(parts[3]) {
		return nil, false
	}
	object := map[string]string{"kind": "ci_log", "system": parts[1], "repo": strings.ReplaceAll(parts[2], "__", "/"), "commit_sha": parts[3]}
	if parts[1] == SystemGitHub {
		object["run_id"] = parts[4]
	} else {
		object["job_id"] = parts[4]
	}
	return object, true
}

// collectCILogs reads the newest runs' (GitHub Actions) or jobs' (GitLab) logs
// of one repository, from Since, at most MaxItems runs or jobs.
func collectCILogs(ctx context.Context, w *writer, req Request) (Result, error) {
	switch req.System {
	case SystemGitHub:
		if !githubRepo.MatchString(req.Repo) {
			return Result{}, fmt.Errorf("%w: a GitHub repository is owner/name", ErrRefused)
		}
		return collectGitHubRuns(ctx, w, req)
	case SystemGitLab:
		if len(req.Repo) > 1024 || !gitlabRepo.MatchString(req.Repo) {
			return Result{}, fmt.Errorf("%w: a GitLab project is its ID or path", ErrRefused)
		}
		return collectGitLabJobs(ctx, w, req)
	default:
		return Result{}, fmt.Errorf("%w: a CI log collection names system github or gitlab", ErrRefused)
	}
}

func collectGitHubRuns(ctx context.Context, w *writer, req Request) (Result, error) {
	res := Result{}
	header := authorization(req)
	header.Set("Accept", "application/vnd.github+json")
	for page := 1; ; page++ {
		q := url.Values{"per_page": {"50"}, "page": {strconv.Itoa(page)}}
		if !req.Since.IsZero() {
			q.Set("created", ">="+req.Since.UTC().Format("2006-01-02T15:04:05Z"))
		}
		body, _, err := get(ctx, req, req.BaseURL+"/repos/"+req.Repo+"/actions/runs?"+q.Encode(), header)
		if err != nil {
			return res, err
		}
		var list struct {
			Runs []struct {
				ID      int64  `json:"id"`
				HeadSHA string `json:"head_sha"`
			} `json:"workflow_runs"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			return res, fmt.Errorf("scancollect: GitHub runs: %w", err)
		}
		for _, run := range list.Runs {
			if res.Items >= req.MaxItems {
				res.Truncated = true
				return res, nil
			}
			if run.ID <= 0 || !commitSHA.MatchString(run.HeadSHA) {
				continue
			}
			archive, _, err := get(ctx, req, req.BaseURL+"/repos/"+req.Repo+"/actions/runs/"+strconv.FormatInt(run.ID, 10)+"/logs", header)
			if err != nil {
				return res, err
			}
			if err := w.unzip(ciFolder(SystemGitHub, req.Repo, run.HeadSHA, strconv.FormatInt(run.ID, 10)), archive); err != nil {
				return res, err
			}
			res.Items++
		}
		if len(list.Runs) < 50 {
			return res, nil
		}
	}
}

func collectGitLabJobs(ctx context.Context, w *writer, req Request) (Result, error) {
	res := Result{}
	header := http.Header{}
	if len(req.Token) > 0 {
		header.Set("PRIVATE-TOKEN", secrettext.String(req.Token))
	}
	project := url.PathEscape(req.Repo)
	for page := 1; ; page++ {
		body, _, err := get(ctx, req, req.BaseURL+"/api/v4/projects/"+project+"/jobs?per_page=100&page="+strconv.Itoa(page), header)
		if err != nil {
			return res, err
		}
		var jobs []struct {
			ID        int64  `json:"id"`
			CreatedAt string `json:"created_at"`
			Commit    struct {
				ID string `json:"id"`
			} `json:"commit"`
		}
		if err := json.Unmarshal(body, &jobs); err != nil {
			return res, fmt.Errorf("scancollect: GitLab jobs: %w", err)
		}
		for _, job := range jobs {
			if res.Items >= req.MaxItems {
				res.Truncated = true
				return res, nil
			}
			if job.ID <= 0 || !commitSHA.MatchString(job.Commit.ID) || (!req.Since.IsZero() && job.CreatedAt != "" && job.CreatedAt < req.Since.UTC().Format("2006-01-02T15:04:05")) {
				continue
			}
			trace, _, err := get(ctx, req, req.BaseURL+"/api/v4/projects/"+project+"/jobs/"+strconv.FormatInt(job.ID, 10)+"/trace", header)
			if err != nil {
				return res, err
			}
			if _, err := w.write(ciFolder(SystemGitLab, req.Repo, job.Commit.ID, strconv.FormatInt(job.ID, 10))+"job.log", trace); err != nil {
				return res, err
			}
			res.Items++
		}
		if len(jobs) < 100 {
			return res, nil
		}
	}
}

// unzip writes the regular files of a log archive under dir.
func (w *writer) unzip(dir string, archive []byte) error {
	if len(archive) > maxLogArchiveBytes {
		return fmt.Errorf("scancollect: a log archive of %d bytes is over the bound", len(archive))
	}
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return fmt.Errorf("scancollect: log archive: %w", err)
	}
	for _, f := range zr.File {
		name := path.Clean("/" + f.Name)[1:]
		if f.FileInfo().IsDir() || !f.Mode().IsRegular() || name == "" {
			continue
		}
		name = ciFolderPart.ReplaceAllString(strings.ReplaceAll(name, "/", "__"), "_")
		r, err := f.Open()
		if err != nil {
			return err
		}
		size := int64(f.UncompressedSize64) // #nosec G115 -- bounded by the archive's own size check below (CWE-190)
		if f.UncompressedSize64 > uint64(maxLayerFileBytes) {
			_ = r.Close()
			continue
		}
		_, err = w.copyFrom(dir+name, io.LimitReader(r, size), size)
		_ = r.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
