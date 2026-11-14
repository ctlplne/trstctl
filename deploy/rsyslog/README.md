# trstctl audit feed: rsyslog receiver content

`trstctl-audit.conf` configures a stock rsyslog to receive the trstctl syslog
audit feed (P5) over TLS on port 6514, keep only trstctl's audit messages,
parse each audit record's JSON (`mmjsonparse`) and write one JSON object per
line to `/var/log/trstctl/audit.json`, ready for any collector that reads
JSON lines.

1. Install rsyslog with its TLS driver and the `mmjsonparse` module.
2. Put the receiver's CA, certificate and key at the three paths in the
   `global()` block, or change the paths.
3. Load the file as rsyslog's configuration, or merge it into yours: rsyslog
   takes one `DefaultNetstreamDriver*` setting.
4. Point a syslog feed at it: `endpoint_url` `syslog+tls://<host>:6514`, and
   `token_ref` naming the receiver's CA certificate when the system roots do
   not cover it.

For mutual TLS (P5-L2), set the `StreamDriver.AuthMode` parameter to
`x509/certvalid`: the feed then needs a `client_cert_ref` holding a
certificate this CA issued.

`trstctl-audit-relp.conf` (P5-L3) receives the same feed over RELP on TLS on
port 2514 instead (rsyslog's `imrelp` input; install its RELP module too), and
keeps, parses and writes the same messages. rsyslog acknowledges each message
as it takes it, and the feed counts a batch delivered only when every message
is acknowledged. Point the feed at `relp+tls://<host>:2514`. A message over
128 KiB ends the session unanswered rather than being truncated, so the feed
retries it instead of counting a cut record delivered.

Each line carries the record's `sequence`, `type`, `chain_hash` and `data`, so
the receiver can drop a repeat by sequence after a batch is resent. Both
receivers are proven against rsyslog 8.2608.0 in the lab.
