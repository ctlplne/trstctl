# Console bundle budget decisions

## Current decision — 2026-10-08

The owner raised the all-JavaScript ceiling from **700 kB to 1,000 kB**. That
measure includes JavaScript for pages the browser fetches only when an operator
opens them, so its former limit was driving removal of useful console content
without improving the initial load. Keep those operator capabilities; when a
page previously cut solely for aggregate size is next changed, restore its useful
content and verify the behavior. The complete startup import graph remains capped
at **240 kB**, and the largest page chunk remains capped at **30 kB**. Those two
limits still protect the bytes a user loads up front and the cost of opening any
single page. `npm run size` enforces all three limits in decimal Brotli bytes.

## Earlier decision — 2026-09-16

The owner set the all-JavaScript ceiling to **700 kB** and the complete startup
import graph ceiling to **240 kB**, replacing the early estimates of 645 kB and
185 kB. Units are decimal bytes compressed with Brotli quality 11.

The product has outgrown those early estimates. The frozen QA candidate measured
678.21 kB for all shipped JavaScript and 229,199 bytes for startup. The subsequent
installed sign-in recovery candidate measured 678.06 kB and 229,220 bytes; its index
chunk alone was only 74,507 bytes. Reporting that index chunk as the startup cost
would omit most of the code the browser actually loads.

The startup checker follows
all static imports, re-exports and HTML modulepreloads, counts shared modules once,
and includes the HTML carrying inline startup code. Dynamic route imports remain
lazy and are excluded from startup, but their JavaScript still counts toward the
all-JavaScript ceiling. Missing or unsupported dependencies fail the check. The
separate largest-page ceiling was set at 30 kB and remains in force.

The 2026-09-16 decision provided room for that product candidate; it did not
reduce loading cost or close QA finding F017. Route lazy-loading remains required.
Preserve these historical measurements and failures when comparing later builds.
