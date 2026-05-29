// Package api exposes the platform's external surfaces: a resource-oriented
// REST API (OpenAPI 3.1) and the gRPC channel for agents.
//
// All errors are returned as RFC 7807 problem+json, mutations honor the
// Idempotency-Key (AN-5), and list endpoints use cursor pagination. The OpenAPI
// 3.1 document is generated from the same route registry that wires the
// handlers, so the spec cannot drift from what is served.
//
// The REST v1 surface (resource CRUD plus identity lifecycle) lands in S3.3; the
// gRPC agent channel is S3.4.
package api
