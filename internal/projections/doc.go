// Package projections builds read models from the event stream (AN-2).
//
// Projection workers consume events and derive the relational read state and
// the audit trail. Read models are always rebuilt from the log and are never
// written directly to represent a state change; replaying the log reproduces
// them deterministically.
//
// Implementation begins in sprint S2.2; this file reserves the package.
package projections
