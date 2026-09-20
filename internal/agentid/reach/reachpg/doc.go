// SPDX-License-Identifier: BUSL-1.1

// Package reachpg holds the ONE database-backed test for the reachability engine: the
// AN-1 RLS negative test that a cross-tenant reachability graph read is denied. It lives
// in its own package so the fast, datastore-free reach unit/property tests never pay the
// cost of standing up embedded PostgreSQL; only this package's TestMain starts it.
package reachpg
