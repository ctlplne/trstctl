<!-- GENERATED FILE — do not edit by hand.
     Regenerate: scripts/ci/extract-claim-traceability.py
     CI verifies freshness with --check. -->

# Patent claim traceability

Every patent-claim citation in the patent-family Go source (`internal/{succession,rpverify,translog,pqcmigration,agentid,reconcile,decommission}` and `ee/`), grouped by family, with the
implementing files and the tests that exercise them. Generated from source, so
it cannot drift from the code it describes.

> **Verification status.** This table proves a *citation* exists, not that the
> cited code practices the claim. The application metadata below and the
> `Verified` column are the only human-maintained data; both are edited in
> `ee/docs/claim-verification.json`, not here. `Converted by` is the deadline to
> convert a US provisional, computed as the filing date plus twelve months.

## Applications

| Family | Subject | Application / provisional no. | Filed | Converted by |
|---|---|---|---|---|
| AGID | _[counsel to supply]_ | _[counsel to supply]_ | 2026-07 | 2027-07 |
| PCAS | _[counsel to supply]_ | _[counsel to supply]_ | 2026-07 | 2027-07 |
| VDEC | _[counsel to supply]_ | _[counsel to supply]_ | 2026-07 | 2027-07 |
| XREC | _[counsel to supply]_ | _[counsel to supply]_ | 2026-07 | 2027-07 |

Citations parsed: **988 qualified**, **0 bare** (bare citations infer their family from the directory — namespace them to remove the guesswork).

## AGID

| Claim | Implementation | Tests | Verified |
|---|---|---|---|
| 1 | `internal/agentid/delegation/bind.go`, `internal/agentid/delegation/brokerstore/precondition.go`, `internal/agentid/delegation/refusal.go` _(+2 more)_ | `internal/agentid/delegation/bind_test.go`, `internal/agentid/delegation/signer_subprocess_test.go` | _[counsel]_ |
| 2 | `internal/agentid/delegation/bind.go`, `internal/agentid/delegation/taskenvelope.go`, `internal/agentid/delegation/verifier.go` _(+3 more)_ | `internal/agentid/delegation/taskenvelope_test.go` | _[counsel]_ |
| 3 | `internal/agentid/delegation/authority.go` | `internal/agentid/delegation/authority_test.go` | _[counsel]_ |
| 4 | `internal/agentid/delegation/authority.go` | `internal/agentid/delegation/authority_test.go` | _[counsel]_ |
| 5 | `internal/agentid/delegation/reachability.go`, `internal/agentid/delegation/verifier.go`, `internal/agentid/delegation/wire.go` _(+4 more)_ | `internal/agentid/delegation/reachability_test.go` | _[counsel]_ |
| 6 | `internal/agentid/delegation/reachability.go`, `internal/agentid/delegation/verifier.go`, `internal/agentid/delegation/wire.go` _(+4 more)_ | `internal/agentid/delegation/reachability_test.go`, `internal/agentid/reach/engine/verdict_test.go` | _[counsel]_ |
| 7 | `internal/agentid/delegation/attestbind.go`, `internal/agentid/delegation/brokerstore/precondition.go`, `internal/agentid/verify/credential.go` _(+3 more)_ | `internal/agentid/delegation/brokerstore/precondition_test.go`, `internal/agentid/verify/nonetwork_test.go`, `internal/agentid/verify/property_test.go` _(+1 more)_ | _[counsel]_ |
| 8 | `internal/agentid/delegation/brokerstore/precondition.go`, `internal/agentid/delegation/brokerstore/renewal.go` | `internal/agentid/delegation/brokerstore/precondition_test.go` | _[counsel]_ |
| 9 | `internal/agentid/delegation/attestbind.go`, `internal/agentid/delegation/brokerstore/precondition.go`, `internal/agentid/delegation/brokerstore/recorder.go` _(+2 more)_ | `internal/agentid/delegation/brokerstore/brokerpg_test.go`, `internal/agentid/delegation/brokerstore/precondition_test.go` | _[counsel]_ |
| 10 | `internal/agentid/api/api.go`, `internal/agentid/delegation/attest.go`, `internal/agentid/delegation/brokerstore/precondition.go` _(+2 more)_ | `internal/agentid/delegation/attest_gate_test.go`, `internal/agentid/delegation/brokerstore/precondition_test.go` | _[counsel]_ |
| 11 | `internal/agentid/agentstack/parse.go`, `internal/agentid/agentstack/representation.go`, `internal/agentid/verify/agentstack_repr.go` | `internal/agentid/agentstack/representation_test.go` | _[counsel]_ |
| 12 | `internal/agentid/agentstack/manifest.go`, `internal/agentid/orchestrator/issuance.go` | `internal/agentid/agentstack/manifest_test.go` | _[counsel]_ |
| 13 | `internal/agentid/delegation/bind.go`, `internal/agentid/delegation/verifier.go` | `internal/agentid/delegation/bind_test.go` | _[counsel]_ |
| 14 | `internal/agentid/delegation/brokerstore/precondition.go`, `internal/agentid/delegation/refusal.go`, `internal/agentid/orchestrator/issuance.go` | `internal/agentid/delegation/bind_test.go`, `internal/agentid/delegation/brokerstore/precondition_test.go` | _[counsel]_ |
| 15 | `internal/agentid/delegation/attestbind.go`, `internal/agentid/delegation/brokerstore/precondition.go` | `internal/agentid/delegation/brokerstore/brokerpg_test.go`, `internal/agentid/delegation/brokerstore/precondition_test.go` | _[counsel]_ |
| 16 | `internal/agentid/delegation/projection.go`, `internal/agentid/delegation/store/store.go`, `internal/agentid/revoke/cascade.go` _(+5 more)_ | `internal/agentid/delegation/store/store_test.go`, `internal/agentid/revoke/cascade_test.go`, `internal/agentid/revoke/execution_test.go` _(+1 more)_ | _[counsel]_ |
| 17 | `internal/agentid/api/api.go`, `internal/agentid/revoke/cascade.go`, `internal/agentid/revoke/directive.go` | `internal/agentid/revoke/cascade_test.go` | _[counsel]_ |
| 18 | `internal/agentid/orchestrator/revocation.go`, `internal/agentid/revoke/aggregate.go`, `internal/agentid/revoke/terminal.go` | `internal/agentid/revoke/aggregate_internal_test.go`, `internal/agentid/revoke/terminal_test.go` | _[counsel]_ |
| 19 | `internal/agentid/api/api.go`, `internal/agentid/revoke/cascade.go`, `internal/agentid/revoke/directive.go` _(+2 more)_ | `internal/agentid/revoke/cascade_test.go` | _[counsel]_ |
| 20 | `internal/agentid/delegation/store/store.go`, `internal/agentid/orchestrator/issuance.go`, `internal/agentid/revoke/refuse_active.go` | `internal/agentid/revoke/refuse_active_test.go` | _[counsel]_ |
| 21 | `internal/agentid/delegation/store/store.go`, `internal/agentid/orchestrator/revocation.go`, `internal/agentid/revoke/directive.go` _(+3 more)_ | `internal/agentid/revoke/execution_test.go`, `internal/agentid/revoke/main_test.go` | _[counsel]_ |
| 22 | `internal/agentid/delegation/store/store.go`, `internal/agentid/revoke/query.go` | `internal/agentid/revoke/terminal_test.go` | _[counsel]_ |
| 23 | `internal/agentid/delegation/store/store.go`, `internal/agentid/orchestrator/revocation.go`, `internal/agentid/revoke/interval.go` | `internal/agentid/revoke/terminal_test.go` | _[counsel]_ |
| 24 | `internal/agentid/delegation/bind.go` | `internal/agentid/delegation/bind_test.go`, `internal/agentid/delegation/store/store_test.go` | _[counsel]_ |
| 25 | `internal/agentid/reach/engine/engine.go`, `internal/agentid/reach/verdict.go` | `internal/agentid/reach/engine/verdict_test.go` | _[counsel]_ |
| 26 | `internal/agentid/delegation/attestbind.go`, `internal/agentid/delegation/brokerstore/precondition.go` | `internal/agentid/delegation/brokerstore/precondition_test.go` | _[counsel]_ |
| 27 | `internal/agentid/agentstack/representation.go`, `internal/agentid/delegation/carriage/carriage.go`, `internal/agentid/delegation/carriage/token.go` _(+2 more)_ | `internal/agentid/delegation/carriage/carriage_test.go` | _[counsel]_ |
| 28 | `internal/agentid/intgate/inventory.go`, `internal/agentid/verify/doc.go`, `internal/agentid/verify/helpers.go` _(+4 more)_ | `internal/agentid/intgate/floor_test.go`, `internal/agentid/verify/verify_test.go`, `internal/agentid/verify/wasm_parity_test.go` | _[counsel]_ |
| 29 | `internal/agentid/verify/agentstack_repr.go`, `internal/agentid/verify/doc.go`, `internal/agentid/verify/policy.go` _(+1 more)_ | `internal/agentid/verify/property_test.go`, `internal/agentid/verify/verify_test.go` | _[counsel]_ |
| 30 | `internal/agentid/delegation/signerwiring.go` | `internal/agentid/delegation/signer_subprocess_test.go` | _[counsel]_ |
| 31 | `internal/agentid/delegation/bind.go`, `internal/agentid/delegation/brokerstore/precondition.go`, `internal/agentid/delegation/verifier.go` _(+2 more)_ | `internal/agentid/delegation/carriage/carriage_test.go`, `internal/agentid/delegation/taskenvelope_test.go`, `internal/agentid/delegation/verifier_test.go` _(+1 more)_ | _[counsel]_ |
| 32 | `internal/agentid/delegation/verifier.go`, `internal/agentid/delegation/wire.go` | `internal/agentid/delegation/attest_gate_test.go` | _[counsel]_ |
| 33 | `internal/agentid/orchestrator/revocation.go`, `internal/agentid/revoke/aggregate.go`, `internal/agentid/revoke/terminal.go` | `internal/agentid/intwire/intwire_test.go`, `internal/agentid/revoke/terminal_test.go` | _[counsel]_ |
| 34 | `internal/agentid/delegation/bind.go` | `internal/agentid/delegation/bind_test.go` | _[counsel]_ |
| 35 | `internal/agentid/delegation/issuancekeyop.go`, `internal/agentid/delegation/verifier.go` | `internal/agentid/delegation/verifier_test.go` | _[counsel]_ |

## PCAS

| Claim | Implementation | Tests | Verified |
|---|---|---|---|
| 1 | `internal/succession/commitment.go`, `internal/succession/doc.go`, `internal/succession/epoch.go` _(+3 more)_ | `internal/succession/conformance/e2e_test.go`, `internal/succession/epoch_test.go`, `internal/succession/minter/minter_test.go` _(+2 more)_ | _[counsel]_ |
| 2 | `internal/succession/retirement/retirement.go`, `internal/succession/retirement/worker.go` | `internal/succession/retirement/retirement_test.go` | _[counsel]_ |
| 3 | `internal/succession/api/api.go`, `internal/succession/events.go`, `internal/succession/retirement/retirement.go` _(+1 more)_ | `internal/succession/api/api_http_test.go`, `internal/succession/retirement/retirement_test.go` | _[counsel]_ |
| 4 | `internal/translog/log.go` | `internal/translog/log_test.go` | _[counsel]_ |
| 5 | `internal/succession/attest.go`, `internal/succession/minter/minter.go`, `internal/succession/minter/spentstore.go` _(+2 more)_ | `internal/succession/minter/minter_test.go`, `internal/succession/minter/spentstore_test.go` | _[counsel]_ |
| 6 | `internal/succession/api/api.go`, `internal/succession/api/service.go`, `internal/succession/orchestrator/orchestrator.go` _(+1 more)_ | `internal/succession/api/api_http_test.go`, `internal/succession/orchestrator/crash_test.go`, `internal/succession/orchestrator/orchestrator_test.go` | _[counsel]_ |
| 7 | `internal/succession/commitment.go`, `internal/succession/store/store.go` | `internal/succession/commitment_test.go`, `internal/succession/store/store_test.go` | _[counsel]_ |
| 8 | `internal/succession/events.go`, `internal/succession/retirement/retirement.go`, `internal/succession/retirement/worker.go` | `internal/succession/retirement/retirement_test.go` | _[counsel]_ |
| 9 | `internal/pqcmigration/succession.go`, `internal/succession/api/api.go` | `internal/pqcmigration/succession_test.go`, `internal/succession/api/api_http_test.go` | _[counsel]_ |
| 10 | `internal/succession/doc.go`, `internal/succession/posture.go` | `internal/succession/posture_test.go` | _[counsel]_ |
| 11 | `internal/succession/events.go`, `internal/succession/monitor/monitor.go` | `internal/succession/monitor/monitor_test.go`, `internal/translog/log_test.go` | _[counsel]_ |
| 12 | `internal/succession/minter/highwater.go`, `internal/succession/minter/hsm.go`, `internal/succession/minter/minter.go` _(+1 more)_ | `internal/succession/minter/minter_test.go`, `internal/succession/signerwiring/floorstore_contract_test.go`, `internal/succession/signerwiring/rpc_integration_test.go` | _[counsel]_ |
| 13 | `internal/rpverify/verifier.go`, `internal/rpverify/wasm/main.go` | `internal/rpverify/verifier_test.go`, `internal/succession/conformance/e2e_test.go`, `internal/succession/record_test.go` | _[counsel]_ |
| 14 | `internal/succession/checkpoint.go` | `internal/succession/checkpoint_test.go` | _[counsel]_ |
| 15 | `internal/succession/commitment.go`, `internal/succession/kem/kem.go`, `internal/succession/kem/signer_mint.go` _(+1 more)_ | `internal/succession/kem/kem_test.go`, `internal/succession/kem/signer_mint_test.go` | _[counsel]_ |
| 16 | `internal/succession/retirement/retirement.go` | `internal/succession/minter/minter_test.go`, `internal/succession/retirement/retirement_test.go` | _[counsel]_ |
| 17 | `internal/rpverify/verifier.go`, `internal/succession/algclass.go`, `internal/succession/exceptional.go` _(+5 more)_ | `internal/rpverify/verifier_test.go`, `internal/succession/minter/strength_test.go` | _[counsel]_ |
| 18 | `internal/rpverify/verifier.go`, `internal/translog/log.go` | `internal/translog/log_test.go` | _[counsel]_ |
| 19 | `internal/succession/agent/agent.go`, `internal/succession/agent/cosignpb/cosign.pb.go`, `internal/succession/agent/cosignpb/cosign_grpc.pb.go` _(+1 more)_ | `internal/succession/agent/agent_test.go`, `internal/succession/agent/transport_test.go` | _[counsel]_ |
| 20 | `internal/succession/issuer/issuer.go` | `internal/succession/issuer/issuer_test.go` | _[counsel]_ |
| 21 | `internal/succession/minter/floorstore_durable.go`, `internal/succession/minter/highwater.go`, `internal/succession/signerwiring/wiring.go` | `internal/succession/minter/floorstore_durable_test.go`, `internal/succession/minter/highwater_test.go` | _[counsel]_ |
| 22 | `internal/succession/doc.go`, `internal/succession/epoch.go`, `internal/succession/transition.go` | `internal/succession/epoch_test.go` | _[counsel]_ |
| 23 | `internal/pqcmigration/succession.go`, `internal/succession/minter/minter.go`, `internal/succession/orchestrator/pqcjob.go` _(+1 more)_ | `internal/succession/minter/minter_test.go`, `internal/succession/orchestrator/pqcjob_test.go` | _[counsel]_ |
| 24 | `internal/succession/commitment.go`, `internal/succession/minter/minter.go`, `internal/succession/policy/provenance.go` _(+1 more)_ | `internal/succession/minter/provenance_test.go`, `internal/succession/policy/provenance_test.go` | _[counsel]_ |
| 25 | `internal/succession/record.go`, `internal/succession/verify.go` | `internal/succession/minter/minter_test.go`, `internal/succession/record_test.go` | _[counsel]_ |
| 26 | `internal/succession/minter/hsm.go` | `internal/succession/minter/hsm_test.go` | _[counsel]_ |
| 27 | `internal/rpverify/issuer.go`, `internal/succession/issuer/issuer.go`, `internal/succession/issuer/x509leaf.go` | `internal/rpverify/issuer_test.go`, `internal/succession/issuer/issuer_test.go`, `internal/succession/issuer/x509leaf_test.go` | _[counsel]_ |
| 28 | `internal/succession/attest.go`, `internal/succession/events.go`, `internal/succession/minter/minter.go` _(+2 more)_ | `internal/succession/attest_golden_test.go`, `internal/succession/evidence_test.go`, `internal/succession/minter/evidence_test.go` _(+2 more)_ | _[counsel]_ |
| 29 | `internal/succession/background/workers.go`, `internal/succession/checkpoint.go` | `internal/succession/background/workers_translog_test.go`, `internal/succession/checkpoint_test.go` | _[counsel]_ |
| 30 | `internal/succession/commitment.go`, `internal/succession/kem/kem.go` | `internal/succession/kem/kem_test.go` | _[counsel]_ |
| 31 | `internal/succession/staple/staple.go` | `internal/succession/staple/staple_test.go` | _[counsel]_ |
| 32 | `internal/succession/staple/staple.go`, `internal/succession/staple/x509carriage.go` | `internal/succession/staple/staple_test.go`, `internal/succession/staple/x509carriage_test.go` | _[counsel]_ |
| 33 | `internal/succession/commitment.go`, `internal/succession/delegation/delegation.go`, `internal/succession/minter/minter.go` | `internal/succession/delegation/delegation_test.go`, `internal/succession/delegation/int13_test.go` | _[counsel]_ |
| 34 | `internal/succession/federation/federation.go` | `internal/succession/federation/federation_test.go` | _[counsel]_ |
| 35 | `internal/rpverify/attested.go`, `internal/succession/attest.go`, `internal/succession/attest/custody.go` _(+3 more)_ | `internal/succession/minter/attested_test.go` | _[counsel]_ |
| 36 | `internal/rpverify/exceptional.go`, `internal/succession/commitment.go`, `internal/succession/exceptional.go` _(+1 more)_ | `internal/succession/exceptional_test.go` | _[counsel]_ |
| 37 | `internal/rpverify/exceptional.go`, `internal/succession/commitment.go`, `internal/succession/exceptional.go` _(+1 more)_ | `internal/rpverify/exceptional_test.go`, `internal/succession/exceptional_test.go` | _[counsel]_ |
| 38 | `internal/succession/audit/replayattest.go` | `internal/succession/audit/replayattest_test.go` | _[counsel]_ |
| 39 | `internal/succession/events.go`, `internal/succession/rewrap/rewrap.go` | `internal/succession/rewrap/rewrap_test.go` | _[counsel]_ |
| 40 | `internal/succession/minter/minter.go`, `internal/succession/policy/provenance.go`, `internal/succession/policy/verifier.go` | `internal/succession/minter/provenance_test.go`, `internal/succession/policy/provenance_test.go` | _[counsel]_ |
| 41 | `internal/succession/events.go`, `internal/succession/minter/minter.go`, `internal/succession/refusal.go` | `internal/succession/evidence_test.go`, `internal/succession/minter/evidence_test.go` | _[counsel]_ |
| 42 | `internal/succession/attest.go`, `internal/succession/commitment.go`, `internal/succession/minter/minter.go` _(+1 more)_ | `internal/succession/attest_golden_test.go`, `internal/succession/evidence_test.go`, `internal/succession/minter/evidence_test.go` | _[counsel]_ |
| 43 | `internal/succession/federation/federation.go` | `internal/succession/federation/federation_test.go` | _[counsel]_ |
| 44 | `internal/succession/federation/federation.go` | `internal/succession/federation/federation_test.go` | _[counsel]_ |
| 45 | `internal/succession/delegation/delegation.go` | `internal/succession/delegation/delegation_test.go` | _[counsel]_ |
| 46 | `internal/succession/delegation/delegation.go` | `internal/succession/delegation/delegation_test.go` | _[counsel]_ |
| 47 | `internal/succession/epoch_derived.go` | `internal/succession/derived_test.go`, `internal/succession/minter/floor_history_test.go` | _[counsel]_ |
| 48 | `internal/succession/minter/floor_history.go` | `internal/succession/minter/floor_history_test.go` | _[counsel]_ |
| 49 | `internal/succession/minter/minter.go` | `internal/succession/minter/floor_history_test.go`, `internal/succession/signerwiring/rpc_integration_test.go` | _[counsel]_ |
| 50 | `internal/succession/doc.go`, `internal/succession/report.go` | `internal/succession/derived_test.go` | _[counsel]_ |

## VDEC

| Claim | Implementation | Tests | Verified |
|---|---|---|---|
| 1 | `internal/decommission/record/record.go` | `internal/decommission/record/record_test.go` | _[counsel]_ |
| 2 | `internal/decommission/verify/verify.go` | `internal/decommission/verify/verify_test.go` | _[counsel]_ |
| 3 | `internal/decommission/reprotect/revokefirst.go` | `internal/decommission/reprotect/revokefirst_test.go` | _[counsel]_ |
| 4 | `internal/decommission/reprotect/staged.go` | `internal/decommission/reprotect/staged_test.go` | _[counsel]_ |
| 5 | `internal/decommission/reprotect/ciphertext.go` | `internal/decommission/reprotect/ciphertext_test.go` | _[counsel]_ |
| 6 | `internal/decommission/reprotect/credential.go` | `internal/decommission/reprotect/credential_test.go` | _[counsel]_ |
| 7 | `internal/decommission/gate/attestclass.go` | `internal/decommission/gate/destroy_test.go` | _[counsel]_ |
| 8 | `internal/decommission/record/countersign.go` | `internal/decommission/record/countersign_test.go` | _[counsel]_ |
| 9 | `internal/decommission/aggregate/aggregate.go` | `internal/decommission/aggregate/aggregate_test.go` | _[counsel]_ |
| 10 | `internal/decommission/aggregate/campaign.go` | `internal/decommission/aggregate/aggregate_test.go` | _[counsel]_ |
| 11 | `internal/decommission/gate/quorum.go`, `internal/decommission/record/ceremony.go` | `internal/decommission/gate/quorum_test.go`, `internal/decommission/record/ceremony_test.go` | _[counsel]_ |
| 12 | `internal/decommission/signerwiring/runtime.go` | `internal/decommission/gate/gate_test.go`, `internal/decommission/record/record_test.go` | _[counsel]_ |
| 13 | `internal/decommission/gate/destroy.go` | `internal/decommission/gate/destroy_test.go` | _[counsel]_ |
| 14 | `internal/decommission/reprotect/completion.go` | `internal/decommission/reprotect/reprotect_test.go` | _[counsel]_ |
| 15 | `internal/decommission/depstate/projection.go` | `internal/decommission/depstate/projection_test.go` | _[counsel]_ |
| 16 | `internal/decommission/verify/verify.go` | `internal/decommission/verify/verify_test.go` | _[counsel]_ |
| 17 | `internal/decommission/verify/verify.go` | `internal/decommission/verify/verify_test.go` | _[counsel]_ |
| 18 | `internal/decommission/aggregate/aggregate.go`, `internal/decommission/verify/verify.go` | `internal/decommission/aggregate/aggregate_test.go`, `internal/decommission/verify/verify_test.go` | _[counsel]_ |
| 19 | `internal/decommission/reprotect/lease.go` | `internal/decommission/reprotect/lease_test.go` | _[counsel]_ |
| 20 | `internal/decommission/aggregate/erasure.go` | `internal/decommission/aggregate/aggregate_test.go` | _[counsel]_ |
| 21 | `internal/decommission/gate/refusal.go` | `internal/decommission/gate/gate_test.go` | _[counsel]_ |
| 22 | `internal/decommission/record/record.go` | `internal/decommission/record/record_test.go` | _[counsel]_ |
| 23 | `internal/decommission/record/record.go` | `internal/decommission/record/record_test.go` | _[counsel]_ |
| 24 | `internal/decommission/verify/wasm/wasm.go` | `internal/decommission/verify/wasm/wasm_test.go` | _[counsel]_ |

## XREC

| Claim | Implementation | Tests | Verified |
|---|---|---|---|
| 1 | `internal/reconcile/doc.go`, `internal/reconcile/rounds/types.go`, `internal/reconcile/runtime.go` | `internal/reconcile/conformance/e2e_integration_test.go`, `internal/reconcile/conformance/storebacked_e2e_test.go` | _[counsel]_ |
| 2 | `internal/reconcile/witness/doc.go`, `internal/reconcile/witness/types.go` | `internal/reconcile/witness/witness_test.go` | _[counsel]_ |
| 3 | `internal/reconcile/rounds/doc.go`, `internal/reconcile/rounds/scheduler.go`, `internal/reconcile/rounds/watermark.go` | `internal/reconcile/rounds/rounds_test.go` | _[counsel]_ |
| 4 | `internal/reconcile/quarantine/doc.go`, `internal/reconcile/quarantine/manager.go` | `internal/reconcile/quarantine/quarantine_test.go` | _[counsel]_ |
| 5 | `internal/reconcile/quarantine/completion.go`, `internal/reconcile/quarantine/doc.go` | `internal/reconcile/quarantine/completion_test.go` | _[counsel]_ |
| 6 | `internal/reconcile/witness/countersign.go`, `internal/reconcile/witness/doc.go` | `internal/reconcile/witness/events_test.go` | _[counsel]_ |
| 7 | `internal/reconcile/witness/doc.go`, `internal/reconcile/witness/majority.go` | `internal/reconcile/witness/majority_test.go` | _[counsel]_ |
| 8 | `internal/reconcile/canon/reducers/doc.go`, `internal/reconcile/canon/reducers/sandbox.go` | `internal/reconcile/canon/reducers/reducers_test.go` | _[counsel]_ |
| 9 | `internal/reconcile/digest/doc.go`, `internal/reconcile/digest/tree.go`, `internal/reconcile/witness/build.go` _(+1 more)_ | `internal/reconcile/digest/digest_test.go`, `internal/reconcile/witness/witness_test.go` | _[counsel]_ |
| 10 | `internal/reconcile/canon/doc.go`, `internal/reconcile/canon/record.go` | `internal/reconcile/canon/canon_test.go` | _[counsel]_ |
| 11 | `internal/reconcile/digest/doc.go`, `internal/reconcile/digest/posture.go`, `internal/reconcile/rounds/doc.go` | `internal/reconcile/digest/digest_test.go` | _[counsel]_ |
| 12 | `internal/reconcile/rounds/doc.go`, `internal/reconcile/rounds/drift.go` | `internal/reconcile/rounds/drift_test.go` | _[counsel]_ |
| 13 | `internal/reconcile/plan/doc.go`, `internal/reconcile/plan/refusal.go` | `internal/reconcile/plan/plan_test.go` | _[counsel]_ |
| 14 | `internal/reconcile/plan/remediation/doc.go`, `internal/reconcile/plan/remediation/manager.go` | `internal/reconcile/plan/remediation/remediation_test.go` | _[counsel]_ |
| 15 | `internal/reconcile/verify/doc.go`, `internal/reconcile/witness/doc.go`, `internal/reconcile/witness/evidence.go` _(+1 more)_ | `internal/reconcile/conformance/storebacked_e2e_test.go`, `internal/reconcile/verify/verify_test.go`, `internal/reconcile/witness/events_test.go` | _[counsel]_ |
| 16 | `internal/reconcile/doc.go`, `internal/reconcile/intgate/doc.go`, `internal/reconcile/runtime.go` | `internal/reconcile/conformance/e2e_integration_test.go`, `internal/reconcile/conformance/storebacked_e2e_test.go`, `internal/reconcile/intgate/rta_strong_test.go` | _[counsel]_ |
| 17 | `internal/reconcile/canon/reducers/doc.go`, `internal/reconcile/canon/reducers/kmip/doc.go`, `internal/reconcile/canon/reducers/registry.go` | `internal/reconcile/canon/reducers/reducers_test.go` | _[counsel]_ |
| 18 | `internal/reconcile/plan/remediation/connector.go`, `internal/reconcile/plan/remediation/doc.go` | `internal/reconcile/plan/remediation/connector_test.go` | _[counsel]_ |
| 19 | `internal/reconcile/witness/doc.go`, `internal/reconcile/witness/ledger.go` | `internal/reconcile/witness/events_test.go` | _[counsel]_ |
| 20 | `internal/reconcile/verify/doc.go`, `internal/reconcile/verify/verify.go` | `internal/reconcile/verify/verify_test.go` | _[counsel]_ |
| 21 | `internal/reconcile/verify/doc.go`, `internal/reconcile/witness/countersign.go`, `internal/reconcile/witness/doc.go` | `internal/reconcile/verify/verify_test.go` | _[counsel]_ |
| 22 | `internal/reconcile/rounds/doc.go`, `internal/reconcile/rounds/watermark.go`, `internal/reconcile/verify/doc.go` | `internal/reconcile/rounds/rounds_test.go`, `internal/reconcile/verify/verify_test.go` | _[counsel]_ |

## Integrity findings

None. Every cited claim has an implementation and a test, no implementation set is a package doc comment alone, and no claim number is ambiguous across families.

