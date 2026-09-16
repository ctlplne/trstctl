// SPDX-License-Identifier: MPL-2.0

//go:build linux

package server

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestBuildRunDepsReleasesLockedNotificationCredentialAfterLaterFailure(t *testing.T) {
	auditKey := testAuditSigningKey(t)
	before := lockedMemoryKiB(t)
	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(t.TempDir(), "audit-signing-key.pem")
	cfg.Notifications.PagerDuty = config.NotificationPagerDuty{
		Enabled: true, Endpoint: "http://127.0.0.1:1/v2/enqueue",
		RoutingKey: []byte("failure-path-pagerduty-key"), Timeout: "1s",
		AllowPrivateCIDRs: []string{"127.0.0.0/8"}, AllowInsecureHTTP: true,
	}
	// This constructor runs immediately after notification construction and
	// fails because no isolated signer was supplied.
	cfg.CodeSigning.Enabled = true
	_, err := buildRunDeps(
		context.Background(), cfg, nil, nil, runSigner{}, runSecrets{},
		slog.New(slog.NewTextHandler(io.Discard, nil)), nil, auditKey,
	)
	if err == nil || !strings.Contains(err.Error(), "isolated signing service") {
		t.Fatalf("buildRunDeps error = %v, want post-notification code-signing failure", err)
	}
	if after := lockedMemoryKiB(t); after != before {
		t.Fatalf("locked memory after failed buildRunDeps = %d KiB, before = %d KiB; notification credential was not released", after, before)
	}
}

func lockedMemoryKiB(t *testing.T) int64 {
	t.Helper()
	file, err := os.Open("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "VmLck:" {
			value, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			return value
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	t.Fatal("/proc/self/status omitted VmLck")
	return 0
}
