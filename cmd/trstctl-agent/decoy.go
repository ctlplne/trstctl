// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/decoy"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// Host-file decoys (Q6-O1). A host agent started with --decoy-ssh-keys plants
// a decoy SSH private key — Ed25519, generated on the host and authorized
// nowhere — at each path where no file is, registers each with the control
// plane by its public half, and watches them: whatever process opens one is
// reported, and the control plane raises the decoy alert naming the program
// and the host. The agent's own inventory scans skip its decoys, and it never
// opens them after planting.
var (
	decoySSHKeys = flag.String("decoy-ssh-keys", "",
		"comma-separated absolute paths where this host agent plants decoy SSH private keys (Ed25519, authorized nowhere) where no file is; any process that opens one raises the decoy alert, naming the program. Linux only: with CAP_SYS_ADMIN fanotify names every opener, otherwise inotify sees each open and names the program only while it still holds the file. Needs the host role")
	decoyStateFile = flag.String("decoy-state-file", "",
		"where the agent records the decoys it planted, so a restart keeps watching them rather than refusing its own files (default: decoys.json beside --key)")
)

const (
	// decoyQueue bounds the opens waiting to be sent; an open past it is
	// counted and dropped, so the watcher never blocks.
	decoyQueue = 256
	// decoyRetry is the wait before a report the control plane did not take
	// is sent again.
	decoyRetry = 10 * time.Second
)

type decoySender interface {
	ReportDecoys(ctx context.Context, req *transport.DecoyReportRequest) (*transport.DecoyReportResponse, error)
}

// decoyWatch is an armed decoy watch (*decoy.Watcher); tests replace it.
type decoyWatch interface {
	Mechanism() string
	Run(ctx context.Context, report func(decoy.Access)) error
}

// decoyPaths splits a --decoy-ssh-keys value.
func decoyPaths(raw string) ([]string, error) {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		if !filepath.IsAbs(p) || len(p) > transport.DecoyPathMaxBytes {
			return nil, fmt.Errorf("--decoy-ssh-keys: %q is not an absolute path of at most %d bytes", p, transport.DecoyPathMaxBytes)
		}
		out = append(out, filepath.Clean(p))
	}
	return out, nil
}

// plantDecoys plants the configured decoys; it runs before the inventory scans
// so they skip the decoys.
func plantDecoys(raw, statePath, keyPath string) ([]decoy.Decoy, error) {
	paths, err := decoyPaths(raw)
	if err != nil || len(paths) == 0 {
		return nil, err
	}
	if strings.TrimSpace(statePath) == "" {
		statePath = filepath.Join(filepath.Dir(keyPath), "decoys.json")
	}
	return decoy.Plant(paths, statePath)
}

// runDecoys registers the planted decoys and then reports every open the
// watcher sees until ctx ends. Registration comes first, since an open of a
// decoy the control plane does not hold is refused; each report is retried
// until the control plane takes it, and opens wait in a bounded queue
// meanwhile. A refusal that a retry cannot change (the agent lacks the host
// role, or the control plane serves no decoys) stops the loop, said once.
func runDecoys(ctx context.Context, planted []decoy.Decoy, sender decoySender, watch decoyWatch, retry time.Duration, log io.Writer) {
	if len(planted) == 0 {
		return
	}
	opens := make(chan decoy.Access, decoyQueue)
	var dropped atomic.Int64
	go func() {
		err := watch.Run(ctx, func(a decoy.Access) {
			select {
			case opens <- a:
			default:
				dropped.Add(1)
			}
		})
		if err != nil && ctx.Err() == nil {
			logDecoy(log, "trstctl-agent: the decoy watcher stopped (%s): %v\n", watch.Mechanism(), err)
		}
	}()
	for start := 0; start < len(planted); start += transport.DecoyReportMaxDecoys {
		req := &transport.DecoyReportRequest{}
		for _, d := range planted[start:min(start+transport.DecoyReportMaxDecoys, len(planted))] {
			req.Decoys = append(req.Decoys, transport.DecoyFile{Path: d.Path, PublicKey: d.PublicKey, PlantedAt: d.PlantedAt})
		}
		resp, err := sendDecoyReport(ctx, sender, req, retry, log, "decoy registration")
		if err != nil {
			return
		}
		logDecoy(log, "trstctl-agent: %d decoy files registered (%d new)\n", resp.Registered+resp.Known, resp.Registered)
	}
	var batch []transport.DecoyOpen
	for {
		if len(batch) == 0 {
			select {
			case <-ctx.Done():
				return
			case a := <-opens:
				batch = append(batch, decoyOpen(a))
			}
		}
	more:
		for len(batch) < transport.DecoyReportMaxOpens {
			select {
			case a := <-opens:
				batch = append(batch, decoyOpen(a))
			default:
				break more
			}
		}
		resp, err := sendDecoyReport(ctx, sender, &transport.DecoyReportRequest{Opens: batch}, retry, log, "decoy open report")
		if errors.Is(err, errDecoyBatchRefused) {
			batch = batch[:0]
			continue
		}
		if err != nil {
			return
		}
		logDecoy(log, "trstctl-agent: reported %d decoy opens (%d recorded, %d with no live decoy)\n", len(batch), resp.Recorded, resp.Rejected)
		if n := dropped.Swap(0); n > 0 {
			logDecoy(log, "trstctl-agent: %d decoy opens were dropped at the queue bound (%d)\n", n, decoyQueue)
		}
		batch = batch[:0]
	}
}

var (
	// errDecoysRefused stops the loop: no retry changes the refusal.
	errDecoysRefused = errors.New("the control plane refuses this agent's decoy reports")
	// errDecoyBatchRefused drops one report the control plane refused as
	// malformed; later opens are still sent.
	errDecoyBatchRefused = errors.New("the control plane refused this decoy report")
)

// sendDecoyReport sends req until the control plane takes it or ctx ends.
func sendDecoyReport(ctx context.Context, sender decoySender, req *transport.DecoyReportRequest, retry time.Duration, log io.Writer, what string) (*transport.DecoyReportResponse, error) {
	for {
		resp, err := sender.ReportDecoys(ctx, req)
		if err == nil {
			return resp, nil
		}
		switch status.Code(err) {
		case codes.PermissionDenied, codes.Unimplemented:
			logDecoy(log, "trstctl-agent: %s refused; decoys are not watched for the control plane: %v\n", what, err)
			return nil, errDecoysRefused
		case codes.InvalidArgument:
			logDecoy(log, "trstctl-agent: %s refused: %v\n", what, err)
			if len(req.Decoys) > 0 {
				return nil, errDecoysRefused
			}
			return nil, errDecoyBatchRefused
		}
		logDecoy(log, "trstctl-agent: %s failed; retrying: %v\n", what, err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(retry):
		}
	}
}

// decoyOpen is one access as the channel carries it. A process names itself
// (its comm), so the name is made printable and cut to the channel's bound:
// an opener cannot get its open refused by its choice of name.
func decoyOpen(a decoy.Access) transport.DecoyOpen {
	process := strings.Map(func(r rune) rune {
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			return '?'
		}
		return r
	}, strings.ToValidUTF8(a.Process, "?"))
	for len(process) > transport.DecoyProcessMaxBytes {
		_, size := utf8.DecodeLastRuneInString(process)
		process = process[:len(process)-size]
	}
	return transport.DecoyOpen{Path: a.Path, At: a.At, PID: a.PID, Process: process, Mechanism: a.Mechanism}
}

// startDecoys plants the configured decoys, arms their watch and runs their
// loop; the returned function stops it. The watch is armed before startDecoys
// returns, so it is in place before the agent's first scan. Decoys need the
// host role (the control plane refuses them from any other agent) and Linux.
func startDecoys(ctx context.Context, roles []string, sender decoySender, keyPath string) func() {
	if strings.TrimSpace(*decoySSHKeys) == "" {
		return func() {}
	}
	if !agentCarriesRole(roles, mtls.AgentRoleHost) {
		fmt.Fprintln(os.Stderr, "trstctl-agent: --decoy-ssh-keys needs the host role; no decoys planted")
		return func() {}
	}
	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "trstctl-agent: --decoy-ssh-keys needs Linux (fanotify or inotify); no decoys planted")
		return func() {}
	}
	planted, err := plantDecoys(*decoySSHKeys, *decoyStateFile, keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent: decoys:", err)
		return func() {}
	}
	watch, err := decoy.Arm(planted)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trstctl-agent: decoys planted but not watched, so not registered:", err)
		return func() {}
	}
	fmt.Printf("trstctl-agent: watching %d decoy files with %s\n", len(planted), watch.Mechanism())
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runDecoys(ctx, planted, sender, watch, decoyRetry, os.Stderr)
	}()
	return func() {
		cancel()
		<-done
	}
}

// logDecoy writes one line of the decoy loop's log; a log that cannot be
// written does not stop the loop.
func logDecoy(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}
