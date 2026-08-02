// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package rounds implements XREC anti-entropy round scheduling and evidence
// records. It compares already-signed state digests, records agreement as of
// their watermarks, and converts stalled or regressed watermarks into staleness
// divergence signals.
//
// Round scheduling over monotone watermarks is XREC-claim-3; the watermark
// carried into the digest posture is XREC-claim-11; drift metrics rebuilt as a
// replayable projection are XREC-claim-12; and a stalled watermark crossing the
// freshness bound is XREC-claim-22.
package rounds
