// SPDX-License-Identifier: MPL-2.0

package cleanpkg

// A package that imports no crypto/* must never be flagged.
import "fmt"

var _ = fmt.Sprint
