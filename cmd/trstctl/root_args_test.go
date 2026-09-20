// SPDX-License-Identifier: BUSL-1.1
package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestRootRejectsUnexpectedPositionalsBeforeConfiguration(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"serve"}, {"--version", "extra"}, {"--", "version"}, {"typo", "--rebuild"}, {"--check-config", "extra"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			// Refuse before attempting a runtime call: a broken parser must not start
			// services in the regression itself.
			_, help, err := parseRootFlags(args, io.Discard)
			if err == nil || help {
				t.Fatalf("unexpected positional input accepted: help=%t error=%v", help, err)
			}
			if !strings.Contains(err.Error(), "--help") {
				t.Fatalf("refusal lacks recovery guidance: %v", err)
			}
			reads := 0
			getenv := func(name string) string {
				reads++
				if name == "TRSTCTL_POSTGRES_MODE" {
					return "external"
				}
				return ""
			}
			var stdout, stderr bytes.Buffer
			if err := run(context.Background(), args, getenv, &stdout, &stderr); err == nil {
				t.Fatal("unknown input reached normal startup")
			}
			if reads != 0 || stdout.Len() != 0 {
				t.Fatalf("unknown input accessed configuration or printed a successful result: reads=%d output=%q", reads, stdout.String())
			}
		})
	}
}

func TestRootPositionalRefusalPreservesSupportedFlags(t *testing.T) {
	for _, args := range [][]string{nil, {"--demo"}, {"--version"}, {"--backup", "/tmp/owned-backup"}, {"--health-check"}} {
		if _, help, err := parseRootFlags(args, io.Discard); err != nil || help {
			t.Fatalf("supported root flags %q rejected: help=%t error=%v", args, help, err)
		}
	}
	for _, arg := range []string{"--help", "-h"} {
		if _, help, err := parseRootFlags([]string{arg}, io.Discard); err != nil || !help {
			t.Fatalf("help changed: %t %v", help, err)
		}
	}
}
