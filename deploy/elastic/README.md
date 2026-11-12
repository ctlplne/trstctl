# trstctl audit feed: Elasticsearch and OpenSearch content

The `elastic` audit feed (P5) posts each audit record, and each batch's chain
trailer, to `https://<host>/<index>/_bulk`. Install these two documents before
the first batch arrives, so the index is created with them:

```sh
curl -X PUT "$ES/_ingest/pipeline/trstctl-audit" -H 'Content-Type: application/json' \
  --data-binary @trstctl-audit-pipeline.json
curl -X PUT "$ES/_index_template/trstctl-audit" -H 'Content-Type: application/json' \
  --data-binary @trstctl-audit-index-template.json
```

Add your credential header (`Authorization: ApiKey …`, or the scheme your
cluster takes) to each call.

- `trstctl-audit-index-template.json` applies to indices named `trstctl-audit*`.
  It maps every field the feed writes. Each event type's own `trstctl.data`
  stays in `_source`, unindexed, so two event types can never conflict over a
  field. The index uses the `trstctl-audit` pipeline by default.
- `trstctl-audit-pipeline.json` marks every document `event.kind:
  trstctl_record` or `chain_trailer`, and copies a trailer's proof
  (`batch_id`, `prev_hash`, `chain_head`, `count`) into `trstctl_trailer`,
  which the template maps as its own fields. A chain head is then a term
  query away: `trstctl_trailer.chain_head: <head>`.

Proven against OpenSearch 3.9.0 in the lab. A stock Elasticsearch takes the
same API calls.
