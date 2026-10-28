// SPDX-License-Identifier: BUSL-1.1

package cmdbexport

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
)

const maxResponseBytes = 1 << 20

func decodeResponse(reader io.Reader, out any) error {
	decoder := json.NewDecoder(io.LimitReader(reader, maxResponseBytes+1))
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("invalid CMDB response: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("CMDB response contains trailing data or exceeds its bound")
	}
	if decoder.InputOffset() > maxResponseBytes {
		return errors.New("CMDB response exceeds its bound")
	}
	return nil
}

// ParseReceipt refuses per-item errors even when IRE returned HTTP 200.
func ParseReceipt(reader io.Reader) (string, error) {
	var response struct {
		Result struct {
			HasError bool `json:"hasError"`
			Items    []struct {
				ClassName  string            `json:"className"`
				SystemID   string            `json:"sysId"`
				Operation  string            `json:"operation"`
				ErrorCount int               `json:"errorCount"`
				Errors     []json.RawMessage `json:"errors"`
			} `json:"items"`
		} `json:"result"`
	}
	if err := decodeResponse(reader, &response); err != nil {
		return "", err
	}
	if response.Result.HasError || len(response.Result.Items) != 1 {
		return "", errors.New("IRE did not accept exactly one certificate CI")
	}
	item := response.Result.Items[0]
	if item.ClassName != CertificateClass || !validSysID(item.SystemID) || item.ErrorCount != 0 || len(item.Errors) != 0 || (item.Operation != "INSERT" && item.Operation != "UPDATE" && item.Operation != "NO_CHANGE") {
		return "", errors.New("IRE certificate item has no successful, bound CI identity")
	}
	return item.SystemID, nil
}

func validSysID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ReadbackEndpoint fixes the table and identifier; the export cannot read a
// general CMDB record or use a server-supplied path as its follow-up URL.
func ReadbackEndpoint(instance, systemID string, values map[string]string) (string, error) {
	if !validSysID(systemID) {
		return "", errors.New("CMDB export returned an invalid CI id")
	}
	endpoint, err := Endpoint(instance, "readback")
	if err != nil {
		return "", err
	}
	u, _ := url.Parse(endpoint)
	u.Path = "/api/now/table/" + CertificateClass + "/" + systemID
	fields := []string{"sys_id"}
	for field := range values {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	q := url.Values{}
	q.Set("sysparm_fields", strings.Join(fields, ","))
	q.Set("sysparm_display_value", "false")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// VerifyReadback compares raw fields from a separate fixed-class GET. Receiver
// acceptance without this match cannot complete the outbox operation.
func VerifyReadback(reader io.Reader, systemID string, values map[string]string) error {
	var response struct {
		Result map[string]string `json:"result"`
	}
	if err := decodeResponse(reader, &response); err != nil {
		return err
	}
	if response.Result["sys_id"] != systemID {
		return errors.New("CMDB certificate readback identifies another CI")
	}
	for field, want := range values {
		if response.Result[field] != want {
			return fmt.Errorf("CMDB certificate readback differs at field %s", field)
		}
	}
	return nil
}
