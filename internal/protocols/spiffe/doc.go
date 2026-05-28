// Package spiffe implements the SPIFFE Workload API, issuing X.509-SVID and
// JWT-SVID over a Unix domain socket for SPIRE-aware workloads.
//
// It is differential-tested against a known-good SPIFFE implementation.
// Implementation begins in sprint S8.2; this file reserves the package.
package spiffe
