# SIEM content packs for the audit feeds

The syslog and Elasticsearch audit feeds (P5) come with receiver content, so a
team can take them without writing a parser or a mapping first (P5-L5). Two
packs ship in the repository and build into deterministic archives:

```sh
make siem-content
# bin/trstctl-elastic-content.tar.gz
# bin/trstctl-rsyslog-content.tar.gz
```

The same sources give the same archive bytes, so a pack can be checked against
its digest.

## Elasticsearch and OpenSearch (`deploy/elastic`)

- `trstctl-audit-index-template.json` applies to indices named
  `trstctl-audit*`. It maps every field the feed writes and keeps each event
  type's own data unindexed, so two event types never conflict over a field and
  fail a batch.
- `trstctl-audit-pipeline.json` marks each document `event.kind:
  trstctl_record` or `chain_trailer`, and maps a trailer's proof as
  `trstctl_trailer` fields (P5-L6).

Install both before the feed's first batch reaches the index; the pack's
README has the two API calls. Proven against OpenSearch 3.9.0.

## rsyslog (`deploy/rsyslog`)

`trstctl-audit.conf` receives the syslog feed over TLS on port 6514, keeps only
trstctl's audit messages (APP-NAME `trstctl`, MSGID `trstctl-audit`), parses
each record's JSON with `mmjsonparse` and writes one JSON object per line. Set
its `StreamDriver.AuthMode` parameter to `x509/certvalid` for a receiver that
requires mutual TLS (P5-L2). Proven against rsyslog 8.2608.0.

`trstctl-audit-relp.conf` (P5-L3) receives the same feed over RELP on TLS on
port 2514 (rsyslog's `imrelp` input) for a feed whose endpoint is
`relp+tls://<host>:2514`, and writes the same JSON lines. rsyslog acknowledges
each message as it takes it, so the feed counts a batch delivered only when
every message is acknowledged; a message over 128 KiB ends the session instead
of being truncated, so it is retried rather than counted. Proven against
rsyslog 8.2608.0 with librelp 1.12.0.

## Splunk

The [Splunk app](splunk-app.md) consumes the Splunk HEC feed.

Publishing the packs to a vendor's marketplace is not part of this repository:
the archives are what a listing would carry.
