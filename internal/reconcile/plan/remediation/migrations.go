// SPDX-License-Identifier: BUSL-1.1

package remediation

import (
	"embed"
	"io/fs"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// MigrationsFS returns the XREC remediation DDL for the core store's
// feature-neutral extension migration seam. It is registered only by the tagged
// EE attach path, so core-only builds apply zero XREC remediation migrations.
func MigrationsFS() fs.FS { return migrationsFS }
