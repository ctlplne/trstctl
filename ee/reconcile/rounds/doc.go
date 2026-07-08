// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package rounds implements XREC anti-entropy round scheduling and evidence
// records. It compares already-signed state digests, records agreement as of
// their watermarks, and converts stalled or regressed watermarks into staleness
// divergence signals.
package rounds
