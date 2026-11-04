// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// runAccessWatch is "trstctl access sessions watch <session-id>" (A255): it
// plays a gateway session's recording from the start and keeps following it
// while the session runs, printing what the client saw (already masked at the
// gateway) and each command, statement and SFTP operation. It ends when the
// recording is sealed.
func runAccessWatch(ctx context.Context, args []string, env Env, stdout, stderr io.Writer, server, token, tenant, caFile string) int {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		_, _ = fmt.Fprintln(stderr, "usage: trstctl access sessions watch <session-id>")
		return 2
	}
	sessionID := args[0]
	client, err := httpClientForEnv(env, caFile)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "trstctl:", err)
		return 1
	}
	next := 0
	for {
		page, err := readRecordingPage(ctx, client, server, token, tenant, sessionID, next)
		if err != nil {
			if ctx.Err() != nil {
				return 0
			}
			_, _ = fmt.Fprintln(stderr, "trstctl:", err)
			return 1
		}
		for _, f := range page.Frames {
			writeRecordingFrame(stdout, f)
		}
		next = page.Next
		if page.Status != "recording" && len(page.Frames) == 0 {
			_, _ = fmt.Fprintf(stdout, "\n[recording %s]\n", page.Status)
			return 0
		}
	}
}

type recordingPage struct {
	Status string           `json:"status"`
	Next   int              `json:"next"`
	Frames []recordingFrame `json:"frames"`
}

type recordingFrame struct {
	Conn   int             `json:"c"`
	Stream string          `json:"s"`
	Data   string          `json:"d"`
	Event  string          `json:"e"`
	From   string          `json:"from"`
	Kind   string          `json:"kind"`
	Text   string          `json:"v"`
	SFTP   json.RawMessage `json:"op"`
}

func readRecordingPage(ctx context.Context, client *http.Client, server, token, tenant, sessionID string, from int) (recordingPage, error) {
	url := strings.TrimRight(server, "/") + "/api/v1/access/sessions/" + sessionID + "/recording/frames?wait=25&from=" + strconv.Itoa(from)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return recordingPage{}, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if tenant != "" {
		req.Header.Set("X-Tenant-ID", tenant)
	}
	resp, err := client.Do(req)
	if err != nil {
		return recordingPage{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode != http.StatusOK {
		return recordingPage{}, fmt.Errorf("read recording: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var page recordingPage
	if err := json.Unmarshal(body, &page); err != nil {
		return recordingPage{}, err
	}
	return page, nil
}

// writeRecordingFrame renders one frame: the bytes the client saw as they
// were, everything else as a bracketed line.
func writeRecordingFrame(w io.Writer, f recordingFrame) {
	switch {
	case f.Stream == "out" || f.Stream == "err":
		if b, err := base64.StdEncoding.DecodeString(f.Data); err == nil {
			_, _ = w.Write(b)
		}
	case f.Stream == "in":
		// What the client typed is echoed back by its terminal; it is
		// in the recording, not repeated on the watch.
	case f.Event == "sftp":
		_, _ = fmt.Fprintf(w, "\n[sftp %s]\n", f.SFTP)
	case f.Event == "connect" || f.Event == "close":
		_, _ = fmt.Fprintf(w, "\n[connection %d %s]\n", f.Conn, f.Event)
	case f.Event != "":
		_, _ = fmt.Fprintf(w, "\n[%s %s] %s\n", f.Event, f.Kind, f.Text)
	}
}
