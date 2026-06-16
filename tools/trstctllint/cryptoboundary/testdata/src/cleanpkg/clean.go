package cleanpkg

// A package that imports no crypto/* must never be flagged.
import "fmt"

var _ = fmt.Sprint
