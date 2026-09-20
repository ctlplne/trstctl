// SPDX-License-Identifier: BUSL-1.1

package cleanpkg

// A package that imports no crypto/* must never be flagged.
import "fmt"

var _ = fmt.Sprint
