package server

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// OpenMigratedStore opens the configured datastore and applies pending migrations
// through the same path Run uses. Internal live gates use it to boot the eval
// stack without depending on test-only helpers.
func OpenMigratedStore(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*store.Store, func() error, error) {
	if cfg == nil {
		return nil, nil, errors.New("server: config is required")
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return openMigratedStore(ctx, cfg, logger)
}
