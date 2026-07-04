// SPDX-License-Identifier: MPL-2.0

// Package projections builds read models from the event stream (AN-2).
//
// Read models are always derived from the log and are never written directly to
// represent a state change; replaying the log reproduces them deterministically.
// There are three ways the read model is advanced, all going through the same
// Projector (the sole read-model writer):
//
//   - Inline (the hot path): the orchestrator projects each served mutation
//     synchronously, in the SAME transaction as the outbox enqueue (AN-6), so a
//     served write is immediately reflected.
//   - Boot replay: Projector.Project replays the whole log on startup so the read
//     model is current before serving.
//   - Tailing worker (SPINE-009): TailWorker runs a DURABLE JetStream consumer over
//     the event stream, applying any event appended out of band (not via the inline
//     path) without waiting for the next boot, and exporting a projection-lag gauge so
//     a stuck/divergent projection is observable. Its cursor is server-side and
//     durable, so a restart resumes from the last applied event. Applying an
//     already-projected event is an idempotent upsert, so the tailer coexists with the
//     inline path.
//
// Projector.Rebuild re-derives the read model from scratch ATOMICALLY (RESIL-003):
// the truncate and the full replay run in one transaction, so an interrupted rebuild
// rolls back rather than leaving a partial inventory. All paths write only through
// internal/store.
//
// Note (EXC-SCALE-01): boot still does a full replay rather than resuming from a
// persisted projection watermark (SPINE-007), and a richer online heal/snapshot is
// future work; the durable tailing cursor + lag metric here are the first step.
package projections
