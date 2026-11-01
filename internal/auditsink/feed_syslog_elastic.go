// SPDX-License-Identifier: BUSL-1.1

package auditsink

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Syslog and Elasticsearch renderings of an audit feed batch (P5). They carry
// the same collector record as the Splunk HEC and Sentinel feeds, one per audit
// record in sequence order, followed by the batch's chain trailer.

const (
	ProviderSyslog  = "syslog"
	ProviderElastic = "elastic"
)

// syslogPRI is facility 13 (log audit) and severity 6 (informational).
const syslogPRI = "<110>"

// writeSyslogBatch writes one RFC 5424 message per record, octet-counted as
// RFC 6587 §3.4.1 and RFC 5425 require on a TLS stream:
//
//	<len> <110>1 <timestamp> - trstctl - trstctl-audit - <collector record JSON>
//
// HOSTNAME and PROCID are nil, so the bytes depend on the batch alone; the
// receiver records the sending host from the connection. The JSON is the same
// record the other feeds carry, including its sequence and chain hash.
func writeSyslogBatch(w io.Writer, records []collectorRecord, times []time.Time) error {
	for i, record := range records {
		body, err := json.Marshal(record)
		if err != nil {
			return err
		}
		msg := syslogPRI + "1 " + times[i].UTC().Format("2006-01-02T15:04:05.000000Z") + " - trstctl - trstctl-audit - " + string(body)
		if _, err := io.WriteString(w, strconv.Itoa(len(msg))+" "+msg); err != nil {
			return err
		}
	}
	return nil
}

type elasticAction struct {
	Create elasticActionMeta `json:"create"`
}

type elasticActionMeta struct {
	ID string `json:"_id"`
}

type elasticDocument struct {
	Timestamp string          `json:"@timestamp"`
	Event     elasticEvent    `json:"event"`
	Labels    elasticLabels   `json:"labels"`
	Trstctl   collectorRecord `json:"trstctl"`
}

type elasticEvent struct {
	ID       string `json:"id"`
	Action   string `json:"action"`
	Sequence uint64 `json:"sequence,omitempty"`
	Dataset  string `json:"dataset"`
}

type elasticLabels struct {
	BatchID string `json:"trstctl_batch_id"`
}

// writeElasticBatch writes an Elasticsearch _bulk body: a create action whose
// _id is the audit record ID, then the document, for each record and the
// trailer. The index comes from the endpoint path (/<index>/_bulk), and a
// create of an ID already indexed is a conflict, not a second copy, so a
// redelivered batch adds nothing.
func writeElasticBatch(w io.Writer, batchID string, records []collectorRecord, times []time.Time) error {
	enc := json.NewEncoder(w)
	for i, record := range records {
		if err := enc.Encode(elasticAction{Create: elasticActionMeta{ID: record.ID}}); err != nil {
			return err
		}
		if err := enc.Encode(elasticDocument{
			Timestamp: times[i].UTC().Format(time.RFC3339Nano),
			Event:     elasticEvent{ID: record.ID, Action: record.Type, Sequence: record.Sequence, Dataset: "trstctl.audit"},
			Labels:    elasticLabels{BatchID: batchID},
			Trstctl:   record,
		}); err != nil {
			return err
		}
	}
	return nil
}

// ElasticBulkResult reads an Elasticsearch _bulk response: every item must be
// created, or already present (409, a redelivery). It returns the number of
// items that failed and the first failing status.
func ElasticBulkResult(body []byte) (failed int, firstStatus int, err error) {
	var resp struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Status int `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, 0, err
	}
	for _, item := range resp.Items {
		for _, result := range item {
			if result.Status == 200 || result.Status == 201 || result.Status == 409 {
				continue
			}
			if failed == 0 {
				firstStatus = result.Status
			}
			failed++
		}
	}
	return failed, firstStatus, nil
}

// SyslogEndpoint reads a syslog+tls://host[:port] endpoint (default port
// 6514, RFC 5425) into the address to dial and the name to verify. Plain TCP
// or UDP syslog is not offered: audit records leave only over TLS.
func SyslogEndpoint(endpoint string) (addr, serverName string, err error) {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme != "syslog+tls" || parsed.Hostname() == "" || parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", errors.New("a syslog endpoint must be syslog+tls://host[:port] with no path, query or credentials")
	}
	port := parsed.Port()
	if port == "" {
		port = "6514"
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", "", fmt.Errorf("syslog endpoint port %q is not a TCP port", port)
	}
	return net.JoinHostPort(parsed.Hostname(), port), parsed.Hostname(), nil
}

// ElasticBulkIndex returns the index an Elasticsearch endpoint path names:
// /<index>/_bulk. The index is the operator's; trstctl writes nowhere else.
func ElasticBulkIndex(path string) (string, error) {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) != 2 || segments[1] != "_bulk" || segments[0] == "" || strings.HasPrefix(segments[0], "_") ||
		segments[0] != strings.ToLower(segments[0]) {
		return "", errors.New("an elastic endpoint must be https://host[:port]/<index>/_bulk with a lowercase index")
	}
	return segments[0], nil
}
