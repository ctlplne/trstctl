// SPDX-License-Identifier: BUSL-1.1

// Package store persists the VDEC dependency-state read model in tenant-scoped
// PostgreSQL tables with row-level security. It is a proprietary EE package
// wired through the core store's feature-neutral extra-migration seam; core
// does not import it and owns only the RLS substrate.
package store
