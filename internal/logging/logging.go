// SPDX-License-Identifier: MPL-2.0

// Package logging builds the application's structured logger: a log/slog logger
// that emits JSON (or text) with a consistent set of fields. It carries no
// business logic.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// Options configures the logger.
type Options struct {
	Level   string // debug | info | warn | error (default info)
	Format  string // json | text (default json)
	Service string // attached as a "service" field on every record, when set
}

// New builds a *slog.Logger writing to w according to opts. It returns an error
// for an unknown level or format.
func New(opts Options, w io.Writer) (*slog.Logger, error) {
	level, err := parseLevel(opts.Level)
	if err != nil {
		return nil, err
	}

	handlerOpts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	switch strings.ToLower(opts.Format) {
	case "", "json":
		handler = slog.NewJSONHandler(w, handlerOpts)
	case "text":
		handler = slog.NewTextHandler(w, handlerOpts)
	default:
		return nil, fmt.Errorf("logging: unknown format %q (want json or text)", opts.Format)
	}

	logger := slog.New(handler)
	if opts.Service != "" {
		logger = logger.With(slog.String("service", opts.Service))
	}
	return logger, nil
}

func parseLevel(level string) (slog.Level, error) {
	switch strings.ToLower(level) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("logging: unknown level %q (want debug, info, warn, or error)", level)
	}
}
