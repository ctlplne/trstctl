# Console bundle budget decision — 2026-09-16

The owner set the all-JavaScript ceiling to **700 kB** and the complete startup
import graph ceiling to **240 kB**, replacing the early estimates of 645 kB and
185 kB. Units are decimal bytes compressed with Brotli quality 11.

The product has outgrown those early estimates. The frozen QA candidate measured
678.21 kB for all shipped JavaScript and 229,199 bytes for startup. The subsequent
installed sign-in recovery candidate measured 678.06 kB and 229,220 bytes; its index
chunk alone was only 74,507 bytes. Reporting that index chunk as the startup cost
would omit most of the code the browser actually loads.

`npm run size` continues to enforce both ceilings. The startup checker follows
all static imports, re-exports and HTML modulepreloads, counts shared modules once,
and includes the HTML carrying inline startup code. Dynamic route imports remain
lazy and are excluded from startup, but their JavaScript still counts toward the
all-JavaScript ceiling. Missing or unsupported dependencies fail the check. The
separate largest-page ceiling remains unchanged at 30 kB.

This is a product-budget decision, not a waiver of a failed check. It provides
room for the current product; it does not reduce loading cost or close QA finding
F017. Route lazy-loading remains the required improvement. Preserve historical
measurements and failures when comparing subsequent builds.
