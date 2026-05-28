// Package protocols groups the credential-issuance and enrollment protocol
// servers, each implemented in its own subpackage: acme (RFC 8555), est
// (RFC 7030), scep (RFC 8894), spiffe (the SPIFFE Workload API), and ssh.
//
// Every protocol parser that touches untrusted input is fuzzed and validated
// by property-based and differential tests, and all signing routes through the
// internal/crypto boundary (AN-3).
//
// The individual servers land across Epoch 4 and Phase 2; this file documents
// the grouping.
package protocols
