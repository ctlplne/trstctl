# trstctl Security Correlations

This app consumes the existing tenant audit feed (`splunk-hec`, sourcetype
`trstctl:audit`). It ships two disabled saved searches: three distinct renewal
failures for one identity, and five distinct certificate revocations for one
tenant, each within 15 minutes. Both deduplicate by tenant and immutable audit
event ID. They are triage signals, not current-state, compromise or recovery proof.

Install the generated `.spl` through your Splunk administrator's normal app
installation process. The app opens its instruction overview without a custom
setup wizard. Its update checks are disabled; install reviewed updates manually.
Each released package must increment its version and positive build identifier. The package contains no credentials, inputs, custom search
commands, role grants or outbound alert actions. It is under the enclosed license.
Splunk itself is a separate vendor product; this package does not grant its use.

1. Create a restricted index and HEC input. Assign the index as that token's
   default; preserve the `trstctl:audit` sourcetype sent by the feed. Use TLS.
2. Configure a tenant audit feed in trstctl at `/audit` or through
   `PUT /api/v1/audit/feeds/{id}`, with provider `splunk-hec`, endpoint ending
   `/services/collector/event`, and a permitted credential reference. Tokens stay
   in the secret source. Private collectors also require explicit private-egress
   authority and CIDRs. Inspect preview, queue, retry and receipt evidence.
3. Put overrides in `local/macros.conf`, never edit the shipped defaults:

   ```ini
   [trstctl_scope]
   definition = index="trstctl_security" tenant_id="YOUR-EXACT-TENANT-ID"
   iseval = 0
   ```

4. Keep the app admin-only until a Splunk administrator grants the intended role
   read access to these app objects and only the authorized index. A macro is a
   search filter, not an isolation boundary: users who can edit searches can
   change it. Prefer a separate index/app scope for each tenant. Defaults contain
   nonmatching index/tenant placeholders; confirm these return zero results.
5. Independently search the index for a known audit `id`, compare `tenant_id`,
   `type`, `time`, `chain_hash` and redacted `data` with trstctl, then dispatch each
   saved search manually against lab events. A collector HTTP2xx receipt is not
   proof that Splunk indexed an event. Missing/redacted identity IDs cannot enter
   the per-identity renewal correlation. Chain trailers are excluded by type.
6. In `local/savedsearches.conf`, set `disabled = false` and `enableSched = 1` for each
   desired saved-search stanza. Leave actions absent unless separately approved.
   The default schedule is every five minutes over the prior 15 minutes.
   Overlapping windows can alert again on the same event set; configure suppression
   in Splunk to fit your incident workflow. Feed retry deduplication does not
   suppress later scheduled alerts.

The repository's owned scaffold checks these exact files and a declared subset
of SPL (`spath`, presence filters, `dedup`, grouped counts/IDs, numeric threshold).
It rejects unsupported syntax. The scaffold evaluates query text ad hoc and labels results `ad_hoc_contract`; it does not enable or schedule the disabled saved searches. Its container proof does not qualify Splunk's
parser, extraction, scheduler, RBAC, version, throughput or alert actions. Run
those checks in an authorized Splunk environment before production use. No
Splunk runtime or vendor certification is included.

Build from the repository root with `make splunk-app`; run local contract tests
with `go test ./deploy/splunk`. See `docs/guides/splunk-app.md` for the complete
operator and scaffold runbook.
