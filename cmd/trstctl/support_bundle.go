// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"trstctl.com/trstctl/internal/supportbundle"
)

func runSupportBundle(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("trstctl support-bundle", flag.ContinueOnError)
	fs.SetOutput(stderr)
	output := fs.String("output", "", "output .tar.gz path (default: timestamped file in the current directory)")
	logFile := fs.String("log-file", "", "optional local log file; only a bounded, secret/PII-redacted tail is included")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("support-bundle: unexpected argument %q", fs.Arg(0))
	}
	path, err := supportbundle.Create(ctx, supportbundle.Options{
		Getenv: getenv, Output: *output, LogFile: *logFile,
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "wrote redacted support bundle to %s\n", path)
	return nil
}
