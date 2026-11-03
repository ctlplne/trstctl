# Runbook: failover

What fails over by itself, how to confirm it did, and what to do when it does
not. The design is in
[High availability](../disaster-recovery.md#high-availability-multi-replica-by-default).

## A control-plane replica or the leader stops

Every replica serves reads and API requests. One replica, the leader, runs the
continuous workers (projection tailer, outbox dispatcher, GC sweeps, CRL
scheduler, audit retention, snapshots) while it holds a PostgreSQL
session-scoped advisory lock. When the leader's process or connection dies,
PostgreSQL releases the lock and a follower takes it within
`TRSTCTL_HA_LEADER_CAMPAIGN_INTERVAL` (3 s by default). Nothing to do but confirm:

1. One replica logs `leader election: this replica is now the leader (running
   continuous background workers)`.
2. `/readyz` answers `200` on the remaining replicas.
3. `trstctl_projection_lag_events` returns toward zero, and the oldest pending
   outbox command on **Deployment health** stops aging.

If no replica logs leadership: check that `TRSTCTL_HA_LEADER_ELECTION` is not
`false` (with more than one replica that reintroduces double projection), and that
the replicas reach PostgreSQL. Do not delete the lock by hand; a lock is held only
by a live session.

## PostgreSQL or NATS fails over

A managed PostgreSQL failover drops every session, including the leader's lock:
replicas reconnect and a leader is elected again. Requests in flight during the
gap can fail; one refused with `503` and `Retry-After` is safe to retry with the
same `Idempotency-Key`.
A NATS node loss is absorbed by JetStream replication (`TRSTCTL_NATS_REPLICAS`,
3 by default).

1. `/readyz` returns to `200`; while NATS durability is degraded it says so, and
   `trstctl_event_log_replicas_actual` is below the desired count.
2. A leader is logged again, as above.
3. If the datastore was lost rather than failed over, this is a restore:
   [Disaster recovery drill](disaster-recovery-drill.md) and
   [Restoring](../disaster-recovery.md#restoring).

## The signer stops

With the default sidecar, each control-plane pod has its own signer over a
shared, read-write-many key store; Kubernetes restarts a stopped signer and
`trstctl_signer_up` returns to `1`. Signing requests during the gap fail closed;
nothing signs without the signer. If the key store or its KEK is lost, follow
[Signer recovery](signer-recovery.md); never generate a new issuing key to get
through an outage.

## Another region

Cross-region failover (federation of a passive region) is an edition
capability: [Cross-cluster federation](../configuration.md#cross-cluster-federation).
Do not promote until the peer cursor and projection lag are inside
`TRSTCTL_FEDERATION_RPO`.
