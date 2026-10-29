# Splunk app: correlate the tenant audit feed

The `deploy/splunk/trstctl` app supplies two saved searches over the existing
`trstctl:audit` HEC stream. Three distinct `identity.renewal_failed` records for
one tenant/identity within 15 minutes trigger the renewal signal. Five distinct
`certificate.revoked` records for one tenant within 15 minutes trigger the
revocation signal. Each result retains the immutable audit event IDs used to
count it. A repeated batch delivery does not increase the count.

These are triage signals. A planned bulk revocation can trigger a burst. A failure
burst does not say that renewal is still failing, and a revocation event does not
prove that a client checked CRL/OCSP or that the workload stopped serving a key.
Inspect the referenced evidence and current product state before acting.

## Package and permissions

From the repository root:

```bash
go test ./deploy/splunk
make splunk-app
```

The deterministic archive is `bin/trstctl-splunk.spl`. It contains only the app's
reviewed configuration, overview, README and repository license. Install through
your authorized Splunk administrator's app-installation workflow. The package
includes no Splunk software, credentials, input definitions, custom commands,
role grants or outbound alert actions. The app opens an instruction overview;
there is no custom setup wizard, and automatic app-update checks are disabled.
Install reviewed updates manually. Splunk runtime use needs its own license
or applicable agreement.

Objects start app-local and admin-only. Saved searches and schedules start
disabled, with nonmatching index/tenant placeholders. Put deployment overrides in
`local/`; keep the package defaults intact. A search macro is a filter, not an
access-control boundary. Have a Splunk administrator restrict each search role's
index access and app-object access. Prefer a dedicated index and app scope per
tenant; users allowed to edit searches can change a macro or remove its filter.

## Connect the actual feed

1. Create an HEC input with a restricted token and dedicated default index. Use
   TLS and `/services/collector/event`. Preserve the `trstctl:audit` sourcetype.
   Set the credential in the server's approved secret source; do not put it in a
   URL or app configuration. Permit its `env:NAME` reference through
   `TRSTCTL_OUTBOUND_ENV_CREDENTIAL_REFS`.
2. In trstctl's `/audit` workspace, preview and save an audit feed with provider
   `splunk-hec`, the collector endpoint and credential reference. The API is
   `PUT /api/v1/audit/feeds/{id}` with `audit:write` and `Idempotency-Key`. The
   native feed uses exact tenant-filtered, privacy-redacted audit batches through
   the durable outbox. Private collectors additionally need `egress:private` and
   explicit destination CIDRs. Do not grant a public-address exception to reach
   a private collector.
3. Inspect lag, queued work, retry state and the collector receipt. A delivered
   HTTP request does not establish indexing. Independently find a known audit
   `id` in Splunk and compare `tenant_id`, `type`, event time, `chain_hash` and
   redacted `data` with trstctl. The generic `siem` notification family uses a
   gateway wire shape; use this native audit feed for the app. Incident-response
   HEC (`trstctl:response`) and OTLP are different streams and do not enter these
   two searches.
4. Configure `local/macros.conf`:

   ```ini
   [trstctl_scope]
   definition = index="trstctl_security" tenant_id="YOUR-EXACT-TENANT-ID"
   iseval = 0
   ```

5. While the saved searches remain disabled, run an ad hoc copy of each query
   with lab records. Check positive thresholds, repeated records, another tenant,
   another identity and records outside the 15-minute window. Missing/redacted
   identity IDs are excluded from the renewal signal. Chain trailers are excluded
   by event type. Verify JSON extraction on the search tier handling your index.
6. Enable each selected search with `disabled = false`, then schedule it with
   `enableSched = 1` in the matching `local/savedsearches.conf` stanza. The default
   schedule is every five minutes over 15 minutes; overlapping windows may alert
   repeatedly on one event set. Configure suppression for your workflow. Alert
   tracking is enabled, but no outbound actions are configured. Have the
   administrator approve actions separately.

If results are absent, check the index/token mapping, exact tenant ID, event time,
feed lag, event type and JSON extraction before changing a query. Keep an ad hoc
search's scope as narrow as the scheduled query. This app does not verify a signed
audit bundle: download JWS evidence and use `trstctl-cli audit verify` for that.

## Owned scaffold proof and its limits

The repository tests read the actual saved-search files. A small contract model
supports only their base filter, `spath`, presence filter, `dedup`, grouped count
and event-ID values, and numeric threshold. Unsupported syntax is an error. The
scaffold evaluates query text ad hoc and labels results `ad_hoc_contract`; it does
not enable or schedule the disabled saved searches. The
scaffold has one request worker, bounded request/state sizes, no outbound calls
and no request-header logging. It is a disposable lab tool, not a SIEM.

Run `deploy/splunk/tools/scaffold.py` in a private Python container with the app
mounted read-only, an owned state file, and a separate fixture token file. Publish
its port only on loopback when the Go test process runs on the host. The script
defaults to loopback; the explicit all-interface bind below is for the isolated
container only:

```text
python3 -B tools/scaffold.py --host 0.0.0.0 --state /state/records.ndjson \
  --token-file /private/token.bin --fail-first-after-store
```

The `--fail-first-after-store` mode deliberately returns503 after storing a batch.
The real outbox retries the same batch; searches must still count each audit ID
once. Use only fabricated lab events and a disposable fixture credential.

The opt-in `TestSplunkAppScaffoldConsumesProductAuditFeed` server test uses only
its reserved owned-fixture origin, `http://127.0.0.1:20489`; it accepts no caller
URL. Publish container port8088 to that loopback port (or run the local fixture
on port20489). Set `TRSTCTL_REQUIRE_SPLUNK_SCAFFOLD=1` to request the test and
`TRSTCTL_A231_SCAFFOLD_DIR` to an owned directory containing
`scaffold-token.bin`. The test opens that fixed file through a directory handle
that refuses path escapes. It creates a unique, operator-allowlisted environment
reference for the disposable token and removes that reference after the run.
Set `TRSTCTL_A231_EXPECT_ACK_LOSS=1` for a fresh/restarted fixture in the
deliberate-loss mode.
The native test log retains an `A231_PUBLIC_PROOF` JSON summary containing only
public lab facts. The test
uses real PostgreSQL, NATS, tenant/feed APIs, the scheduler and outbox, then reads
exact correlation results independently. Its input audit records are seeded lab
events; producer lifecycle and upstream CA effects need separate journey proof.

This scaffold does not qualify Splunk's parser, JSON extraction, scheduler,
RBAC, vendor version, throughput or alert actions. Those remain unverified until
the same package and lab events are exercised in an authorized Splunk runtime.
Record the product version, package digest, query/result IDs, retry and tenant
cases, scheduler firings and role checks during that run. An HTTP2xx or scaffold
result must not be reported as that vendor proof.

Protocol and configuration references:
[HEC event format](https://help.splunk.com/en/splunk-cloud-platform/get-started/get-data-in/10.6/get-data-with-http-event-collector/format-events-for-http-event-collector),
[savedsearches.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/configuration-file-reference/10.2.8-configuration-file-reference/savedsearches.conf),
and [app.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/configuration-file-reference/10.6.0-configuration-file-reference/app.conf).
