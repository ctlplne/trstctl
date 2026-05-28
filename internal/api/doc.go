// Package api exposes the platform's external surfaces: a resource-oriented
// REST API (OpenAPI 3.1) and the gRPC channel for agents.
//
// All errors are returned as RFC 7807 problem+json, mutations honor the
// Idempotency-Key (AN-5), and list endpoints use cursor pagination.
//
// Implementation begins in sprint S3.3; this file reserves the package.
package api
