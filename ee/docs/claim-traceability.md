<!-- GENERATED FILE — do not edit by hand.
     Regenerate: scripts/ci/extract-claim-traceability.py
     CI verifies freshness with --check. -->

# Patent claim traceability

Every patent-claim citation in `ee/` Go source, grouped by family, with the
implementing files and the tests that exercise them. Generated from source, so
it cannot drift from the code it describes.

> **Verification status.** This table proves a *citation* exists, not that the
> cited code practices the claim. The `Verified` column is maintained by counsel
> review and is the only column a human edits — in `claim-verification.yaml`,
> not here.

## Applications

| Family | Subject | Application / provisional no. | Filed | Converted by |
|---|---|---|---|---|
| AGID | _[FILL]_ | _[FILL]_ | _[FILL]_ | _[FILL: filing + 12 months]_ |
| PCAS | _[FILL]_ | _[FILL]_ | _[FILL]_ | _[FILL: filing + 12 months]_ |
| VDEC | _[FILL]_ | _[FILL]_ | _[FILL]_ | _[FILL: filing + 12 months]_ |

Citations parsed: **831 qualified**, **0 bare** (bare citations infer their family from the directory — namespace them to remove the guesswork).

## AGID

| Claim | Implementation | Tests | Verified |
|---|---|---|---|
| 1 | `ee/agentid/delegation/bind.go`, `ee/agentid/delegation/brokerstore/precondition.go`, `ee/agentid/delegation/refusal.go` _(+1 more)_ | `ee/agentid/delegation/bind_test.go` | _[counsel]_ |
| 2 | `ee/agentid/delegation/bind.go`, `ee/agentid/delegation/taskenvelope.go`, `ee/agentid/delegation/verifier.go` _(+3 more)_ | `ee/agentid/delegation/taskenvelope_test.go` | _[counsel]_ |
| 3 | `ee/agentid/delegation/authority.go` | `ee/agentid/delegation/authority_test.go` | _[counsel]_ |
| 4 | `ee/agentid/delegation/authority.go` | `ee/agentid/delegation/authority_test.go` | _[counsel]_ |
| 5 | `ee/agentid/delegation/reachability.go`, `ee/agentid/delegation/verifier.go`, `ee/agentid/delegation/wire.go` _(+4 more)_ | `ee/agentid/delegation/reachability_test.go` | _[counsel]_ |
| 6 | `ee/agentid/delegation/reachability.go`, `ee/agentid/delegation/verifier.go`, `ee/agentid/delegation/wire.go` _(+4 more)_ | `ee/agentid/delegation/reachability_test.go`, `ee/agentid/reach/engine/verdict_test.go` | _[counsel]_ |
| 7 | `ee/agentid/delegation/attestbind.go`, `ee/agentid/delegation/brokerstore/precondition.go`, `ee/agentid/verify/credential.go` _(+3 more)_ | `ee/agentid/delegation/brokerstore/precondition_test.go`, `ee/agentid/verify/nonetwork_test.go`, `ee/agentid/verify/property_test.go` _(+1 more)_ | _[counsel]_ |
| 8 | `ee/agentid/delegation/brokerstore/precondition.go`, `ee/agentid/delegation/brokerstore/renewal.go` | `ee/agentid/delegation/brokerstore/precondition_test.go` | _[counsel]_ |
| 9 | `ee/agentid/delegation/attestbind.go`, `ee/agentid/delegation/brokerstore/precondition.go`, `ee/agentid/delegation/brokerstore/recorder.go` _(+2 more)_ | `ee/agentid/delegation/brokerstore/brokerpg_test.go`, `ee/agentid/delegation/brokerstore/precondition_test.go` | _[counsel]_ |
| 10 | `ee/agentid/api/api.go`, `ee/agentid/delegation/attest.go`, `ee/agentid/delegation/brokerstore/precondition.go` _(+2 more)_ | `ee/agentid/delegation/attest_gate_test.go`, `ee/agentid/delegation/brokerstore/precondition_test.go` | _[counsel]_ |
| 11 | `ee/agentid/agentstack/parse.go`, `ee/agentid/agentstack/representation.go`, `ee/agentid/verify/agentstack_repr.go` | `ee/agentid/agentstack/representation_test.go` | _[counsel]_ |
| 12 | `ee/agentid/agentstack/manifest.go`, `ee/agentid/orchestrator/issuance.go` | `ee/agentid/agentstack/manifest_test.go` | _[counsel]_ |
| 13 | `ee/agentid/delegation/bind.go`, `ee/agentid/delegation/verifier.go` | `ee/agentid/delegation/bind_test.go` | _[counsel]_ |
| 14 | `ee/agentid/delegation/brokerstore/precondition.go`, `ee/agentid/delegation/refusal.go`, `ee/agentid/orchestrator/issuance.go` | `ee/agentid/delegation/bind_test.go`, `ee/agentid/delegation/brokerstore/precondition_test.go` | _[counsel]_ |
| 15 | `ee/agentid/delegation/attestbind.go`, `ee/agentid/delegation/brokerstore/precondition.go` | `ee/agentid/delegation/brokerstore/brokerpg_test.go`, `ee/agentid/delegation/brokerstore/precondition_test.go` | _[counsel]_ |
| 16 | `ee/agentid/delegation/projection.go`, `ee/agentid/delegation/store/store.go`, `ee/agentid/revoke/cascade.go` _(+5 more)_ | `ee/agentid/delegation/store/store_test.go`, `ee/agentid/revoke/cascade_test.go`, `ee/agentid/revoke/execution_test.go` _(+1 more)_ | _[counsel]_ |
| 17 | `ee/agentid/api/api.go`, `ee/agentid/revoke/cascade.go`, `ee/agentid/revoke/directive.go` | `ee/agentid/revoke/cascade_test.go` | _[counsel]_ |
| 18 | `ee/agentid/orchestrator/revocation.go`, `ee/agentid/revoke/aggregate.go`, `ee/agentid/revoke/terminal.go` | `ee/agentid/revoke/terminal_test.go` | _[counsel]_ |
| 19 | `ee/agentid/api/api.go`, `ee/agentid/revoke/cascade.go`, `ee/agentid/revoke/directive.go` _(+2 more)_ | `ee/agentid/revoke/cascade_test.go` | _[counsel]_ |
| 20 | `ee/agentid/delegation/store/store.go`, `ee/agentid/orchestrator/issuance.go`, `ee/agentid/revoke/refuse_active.go` | `ee/agentid/revoke/refuse_active_test.go` | _[counsel]_ |
| 21 | `ee/agentid/delegation/store/store.go`, `ee/agentid/orchestrator/revocation.go`, `ee/agentid/revoke/directive.go` _(+3 more)_ | `ee/agentid/revoke/execution_test.go`, `ee/agentid/revoke/main_test.go` | _[counsel]_ |
| 22 | `ee/agentid/delegation/store/store.go`, `ee/agentid/revoke/query.go` | `ee/agentid/revoke/terminal_test.go` | _[counsel]_ |
| 23 | `ee/agentid/delegation/store/store.go`, `ee/agentid/orchestrator/revocation.go`, `ee/agentid/revoke/interval.go` | `ee/agentid/revoke/terminal_test.go` | _[counsel]_ |
| 24 | `ee/agentid/delegation/bind.go` | `ee/agentid/delegation/bind_test.go`, `ee/agentid/delegation/store/store_test.go` | _[counsel]_ |
| 25 | `ee/agentid/reach/engine/engine.go`, `ee/agentid/reach/verdict.go` | `ee/agentid/reach/engine/verdict_test.go` | _[counsel]_ |
| 26 | `ee/agentid/delegation/attestbind.go`, `ee/agentid/delegation/brokerstore/precondition.go` | `ee/agentid/delegation/brokerstore/precondition_test.go` | _[counsel]_ |
| 27 | `ee/agentid/agentstack/representation.go`, `ee/agentid/delegation/carriage/carriage.go`, `ee/agentid/delegation/carriage/token.go` _(+2 more)_ | `ee/agentid/delegation/carriage/carriage_test.go` | _[counsel]_ |
| 28 | `ee/agentid/intgate/doc.go`, `ee/agentid/intgate/inventory.go`, `ee/agentid/verify/doc.go` _(+5 more)_ | `ee/agentid/intgate/floor_test.go`, `ee/agentid/verify/verify_test.go`, `ee/agentid/verify/wasm_parity_test.go` | _[counsel]_ |
| 29 | `ee/agentid/verify/agentstack_repr.go`, `ee/agentid/verify/doc.go`, `ee/agentid/verify/policy.go` _(+1 more)_ | `ee/agentid/verify/property_test.go`, `ee/agentid/verify/verify_test.go` | _[counsel]_ |
| 31 | `ee/agentid/delegation/bind.go`, `ee/agentid/delegation/brokerstore/precondition.go`, `ee/agentid/delegation/verifier.go` _(+2 more)_ | `ee/agentid/delegation/carriage/carriage_test.go`, `ee/agentid/delegation/taskenvelope_test.go`, `ee/agentid/delegation/verifier_test.go` _(+1 more)_ | _[counsel]_ |
| 32 | `ee/agentid/delegation/verifier.go`, `ee/agentid/delegation/wire.go` | `ee/agentid/delegation/attest_gate_test.go` | _[counsel]_ |
| 33 | `ee/agentid/orchestrator/revocation.go`, `ee/agentid/revoke/aggregate.go`, `ee/agentid/revoke/terminal.go` | `ee/agentid/intwire/intwire_test.go`, `ee/agentid/revoke/terminal_test.go` | _[counsel]_ |
| 34 | `ee/agentid/delegation/bind.go` | `ee/agentid/delegation/bind_test.go` | _[counsel]_ |

## PCAS

| Claim | Implementation | Tests | Verified |
|---|---|---|---|
| 1 | `ee/succession/commitment.go`, `ee/succession/doc.go`, `ee/succession/epoch.go` _(+3 more)_ | `ee/succession/conformance/e2e_test.go`, `ee/succession/epoch_test.go`, `ee/succession/minter/minter_test.go` _(+2 more)_ | _[counsel]_ |
| 2 | `ee/succession/retirement/retirement.go`, `ee/succession/retirement/worker.go` | `ee/succession/retirement/retirement_test.go` | _[counsel]_ |
| 3 | `ee/succession/api/api.go`, `ee/succession/events.go`, `ee/succession/retirement/retirement.go` _(+1 more)_ | `ee/succession/api/api_http_test.go`, `ee/succession/retirement/retirement_test.go` | _[counsel]_ |
| 4 | `ee/translog/log.go` | `ee/translog/log_test.go` | _[counsel]_ |
| 5 | `ee/succession/attest.go`, `ee/succession/minter/minter.go`, `ee/succession/minter/spentstore.go` _(+2 more)_ | `ee/succession/minter/minter_test.go`, `ee/succession/minter/spentstore_test.go` | _[counsel]_ |
| 6 | `ee/succession/api/api.go`, `ee/succession/api/service.go`, `ee/succession/orchestrator/orchestrator.go` _(+1 more)_ | `ee/succession/api/api_http_test.go`, `ee/succession/orchestrator/crash_test.go`, `ee/succession/orchestrator/orchestrator_test.go` | _[counsel]_ |
| 7 | `ee/succession/commitment.go`, `ee/succession/store/store.go` | `ee/succession/commitment_test.go`, `ee/succession/store/store_test.go` | _[counsel]_ |
| 8 | `ee/succession/events.go`, `ee/succession/retirement/retirement.go`, `ee/succession/retirement/worker.go` | `ee/succession/retirement/retirement_test.go` | _[counsel]_ |
| 9 | `ee/pqcmigration/succession.go`, `ee/succession/api/api.go` | `ee/pqcmigration/succession_test.go`, `ee/succession/api/api_http_test.go` | _[counsel]_ |
| 10 | `ee/succession/doc.go`, `ee/succession/posture.go` | `ee/succession/posture_test.go` | _[counsel]_ |
| 11 | `ee/succession/events.go`, `ee/succession/monitor/monitor.go` | `ee/succession/monitor/monitor_test.go`, `ee/translog/log_test.go` | _[counsel]_ |
| 12 | `ee/succession/minter/highwater.go`, `ee/succession/minter/hsm.go`, `ee/succession/minter/minter.go` _(+1 more)_ | `ee/succession/minter/minter_test.go`, `ee/succession/signerwiring/floorstore_contract_test.go`, `ee/succession/signerwiring/rpc_integration_test.go` | _[counsel]_ |
| 13 | `ee/rpverify/verifier.go`, `ee/rpverify/wasm/main.go` | `ee/rpverify/verifier_test.go`, `ee/succession/conformance/e2e_test.go`, `ee/succession/record_test.go` | _[counsel]_ |
| 14 | `ee/succession/checkpoint.go` | `ee/succession/checkpoint_test.go` | _[counsel]_ |
| 15 | `ee/succession/commitment.go`, `ee/succession/kem/kem.go`, `ee/succession/kem/signer_mint.go` _(+1 more)_ | `ee/succession/kem/kem_test.go`, `ee/succession/kem/signer_mint_test.go` | _[counsel]_ |
| 16 | `ee/succession/retirement/retirement.go` | `ee/succession/minter/minter_test.go`, `ee/succession/retirement/retirement_test.go` | _[counsel]_ |
| 17 | `ee/rpverify/verifier.go`, `ee/succession/algclass.go`, `ee/succession/exceptional.go` _(+5 more)_ | `ee/rpverify/verifier_test.go`, `ee/succession/minter/strength_test.go` | _[counsel]_ |
| 18 | `ee/rpverify/verifier.go`, `ee/translog/log.go` | `ee/translog/log_test.go` | _[counsel]_ |
| 19 | `ee/succession/agent/agent.go`, `ee/succession/agent/cosignpb/cosign.pb.go`, `ee/succession/agent/cosignpb/cosign_grpc.pb.go` _(+1 more)_ | `ee/succession/agent/agent_test.go`, `ee/succession/agent/transport_test.go` | _[counsel]_ |
| 20 | `ee/succession/issuer/issuer.go` | `ee/succession/issuer/issuer_test.go` | _[counsel]_ |
| 21 | `ee/succession/minter/floorstore_durable.go`, `ee/succession/minter/highwater.go`, `ee/succession/signerwiring/wiring.go` | `ee/succession/minter/floorstore_durable_test.go`, `ee/succession/minter/highwater_test.go` | _[counsel]_ |
| 22 | `ee/succession/doc.go`, `ee/succession/epoch.go`, `ee/succession/transition.go` | `ee/succession/epoch_test.go` | _[counsel]_ |
| 23 | `ee/pqcmigration/succession.go`, `ee/succession/minter/minter.go`, `ee/succession/orchestrator/pqcjob.go` _(+1 more)_ | `ee/succession/minter/minter_test.go`, `ee/succession/orchestrator/pqcjob_test.go` | _[counsel]_ |
| 24 | `ee/succession/commitment.go`, `ee/succession/minter/minter.go`, `ee/succession/policy/provenance.go` _(+1 more)_ | `ee/succession/minter/provenance_test.go`, `ee/succession/policy/provenance_test.go` | _[counsel]_ |
| 25 | `ee/succession/record.go`, `ee/succession/verify.go` | `ee/succession/minter/minter_test.go`, `ee/succession/record_test.go` | _[counsel]_ |
| 26 | `ee/succession/minter/hsm.go` | `ee/succession/minter/hsm_test.go` | _[counsel]_ |
| 27 | `ee/rpverify/issuer.go`, `ee/succession/issuer/issuer.go`, `ee/succession/issuer/x509leaf.go` | `ee/rpverify/issuer_test.go`, `ee/succession/issuer/issuer_test.go`, `ee/succession/issuer/x509leaf_test.go` | _[counsel]_ |
| 28 | `ee/succession/attest.go`, `ee/succession/events.go`, `ee/succession/minter/minter.go` _(+2 more)_ | `ee/succession/attest_golden_test.go`, `ee/succession/evidence_test.go`, `ee/succession/minter/evidence_test.go` _(+2 more)_ | _[counsel]_ |
| 29 | `ee/succession/background/workers.go`, `ee/succession/checkpoint.go` | `ee/succession/background/workers_translog_test.go`, `ee/succession/checkpoint_test.go` | _[counsel]_ |
| 30 | `ee/succession/commitment.go`, `ee/succession/kem/kem.go` | `ee/succession/kem/kem_test.go` | _[counsel]_ |
| 31 | `ee/succession/staple/staple.go` | `ee/succession/staple/staple_test.go` | _[counsel]_ |
| 32 | `ee/succession/staple/staple.go`, `ee/succession/staple/x509carriage.go` | `ee/succession/staple/staple_test.go`, `ee/succession/staple/x509carriage_test.go` | _[counsel]_ |
| 33 | `ee/succession/commitment.go`, `ee/succession/delegation/delegation.go`, `ee/succession/minter/minter.go` | `ee/succession/delegation/delegation_test.go`, `ee/succession/delegation/int13_test.go` | _[counsel]_ |
| 34 | `ee/succession/federation/federation.go` | `ee/succession/federation/federation_test.go` | _[counsel]_ |
| 35 | `ee/rpverify/attested.go`, `ee/succession/attest.go`, `ee/succession/attest/custody.go` _(+3 more)_ | `ee/succession/minter/attested_test.go` | _[counsel]_ |
| 36 | `ee/rpverify/exceptional.go`, `ee/succession/commitment.go`, `ee/succession/exceptional.go` _(+1 more)_ | `ee/succession/exceptional_test.go` | _[counsel]_ |
| 37 | `ee/rpverify/exceptional.go`, `ee/succession/commitment.go`, `ee/succession/exceptional.go` _(+1 more)_ | `ee/rpverify/exceptional_test.go`, `ee/succession/exceptional_test.go` | _[counsel]_ |
| 38 | `ee/succession/audit/replayattest.go` | `ee/succession/audit/replayattest_test.go` | _[counsel]_ |
| 39 | `ee/succession/events.go`, `ee/succession/rewrap/rewrap.go` | `ee/succession/rewrap/rewrap_test.go` | _[counsel]_ |
| 40 | `ee/succession/minter/minter.go`, `ee/succession/policy/provenance.go`, `ee/succession/policy/verifier.go` | `ee/succession/minter/provenance_test.go`, `ee/succession/policy/provenance_test.go` | _[counsel]_ |
| 41 | `ee/succession/events.go`, `ee/succession/minter/minter.go`, `ee/succession/refusal.go` | `ee/succession/evidence_test.go`, `ee/succession/minter/evidence_test.go` | _[counsel]_ |
| 42 | `ee/succession/attest.go`, `ee/succession/commitment.go`, `ee/succession/minter/minter.go` _(+1 more)_ | `ee/succession/attest_golden_test.go`, `ee/succession/evidence_test.go`, `ee/succession/minter/evidence_test.go` | _[counsel]_ |
| 43 | `ee/succession/federation/federation.go` | `ee/succession/federation/federation_test.go` | _[counsel]_ |
| 44 | `ee/succession/federation/federation.go` | `ee/succession/federation/federation_test.go` | _[counsel]_ |
| 45 | `ee/succession/delegation/delegation.go` | `ee/succession/delegation/delegation_test.go` | _[counsel]_ |
| 46 | `ee/succession/delegation/delegation.go` | `ee/succession/delegation/delegation_test.go` | _[counsel]_ |
| 47 | `ee/succession/epoch_derived.go` | `ee/succession/derived_test.go`, `ee/succession/minter/floor_history_test.go` | _[counsel]_ |
| 48 | `ee/succession/minter/floor_history.go` | `ee/succession/minter/floor_history_test.go` | _[counsel]_ |
| 49 | `ee/succession/minter/minter.go` | `ee/succession/minter/floor_history_test.go`, `ee/succession/signerwiring/rpc_integration_test.go` | _[counsel]_ |
| 50 | `ee/succession/doc.go`, `ee/succession/report.go` | `ee/succession/derived_test.go` | _[counsel]_ |

## VDEC

| Claim | Implementation | Tests | Verified |
|---|---|---|---|
| 1 | `ee/decommission/record/record.go` | `ee/decommission/record/record_test.go` | _[counsel]_ |

## Integrity findings

None. Every cited claim has an implementation and a test, no implementation set is a package doc comment alone, and no claim number is ambiguous across families.

