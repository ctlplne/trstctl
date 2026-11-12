// SPDX-License-Identifier: BUSL-1.1

// Package elastic checks the Elasticsearch and OpenSearch content shipped for
// the trstctl audit feed (P5-L6): the index template and ingest pipeline map
// every field the feed writes, the chain trailer's proof as its own fields.
package elastic
