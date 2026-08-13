// SPDX-License-Identifier: MPL-2.0

package cryptoreadiness

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

const (
	MaxExportItems = 10000
	maxExportBytes = 16 << 20
)

// CSV returns a strict spreadsheet-safe export of the same ordered items.
func CSV(dataset Dataset) ([]byte, error) {
	if len(dataset.Items) > MaxExportItems {
		return nil, fmt.Errorf("crypto readiness export exceeds %d items", MaxExportItems)
	}
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write([]string{
		"sequence", "dataset_digest", "asset_id", "asset_name", "exhibitors",
		"dependents", "owners", "quantum_vulnerable", "out_of_policy", "unlocated",
		"recommendation", "actions", "evidence_refs", "coverage_guidance",
	}); err != nil {
		return nil, err
	}
	for index, item := range dataset.Items {
		evidence := []string{}
		for _, action := range item.Actions {
			evidence = append(evidence, action.EvidenceRefs...)
		}
		exhibitors, err := jsonCell(item.Exhibitors)
		if err != nil {
			return nil, err
		}
		dependents, err := jsonCell(item.Dependents)
		if err != nil {
			return nil, err
		}
		owners, err := jsonCell(item.Owners)
		if err != nil {
			return nil, err
		}
		actions, err := jsonCell(item.Actions)
		if err != nil {
			return nil, err
		}
		evidenceCell, err := jsonCell(sortedUnique(evidence))
		if err != nil {
			return nil, err
		}
		record := []string{
			strconv.Itoa(index + 1), dataset.DatasetDigest, item.Asset.ID, item.Asset.Name,
			exhibitors, dependents, owners,
			strconv.FormatBool(item.QuantumVulnerable), strconv.FormatBool(item.OutOfPolicy),
			strconv.FormatBool(item.Unlocated), item.Recommendation, actions,
			evidenceCell, dataset.CoverageGuidance,
		}
		for column := range record {
			record[column] = spreadsheetSafe(record[column])
		}
		if err := w.Write(record); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	if buf.Len() > maxExportBytes {
		return nil, fmt.Errorf("crypto readiness CSV exceeds %d bytes", maxExportBytes)
	}
	return buf.Bytes(), nil
}

// NDJSON returns one bounded, independently parseable item per line.
func NDJSON(dataset Dataset) ([]byte, error) {
	if len(dataset.Items) > MaxExportItems {
		return nil, fmt.Errorf("crypto readiness export exceeds %d items", MaxExportItems)
	}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	for index, item := range dataset.Items {
		line := struct {
			Format           string `json:"format"`
			TenantID         string `json:"tenant_id"`
			Sequence         int    `json:"sequence"`
			DatasetDigest    string `json:"dataset_digest"`
			Urgent           int    `json:"urgent"`
			Unlocated        int    `json:"unlocated"`
			CoverageGuidance string `json:"coverage_guidance"`
			Item             Item   `json:"item"`
		}{dataset.Format, dataset.TenantID, index + 1, dataset.DatasetDigest, dataset.Urgent, dataset.Unlocated, dataset.CoverageGuidance, item}
		if err := encoder.Encode(line); err != nil {
			return nil, err
		}
		if buf.Len() > maxExportBytes {
			return nil, fmt.Errorf("crypto readiness NDJSON exceeds %d bytes", maxExportBytes)
		}
	}
	return buf.Bytes(), nil
}

func jsonCell(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// spreadsheetSafe prevents a discovered name or recommendation from becoming
// a formula when an operator opens the CSV. Structured cells start with JSON
// brackets/braces and retain exact machine-readable values.
func spreadsheetSafe(value string) string {
	trimmed := strings.TrimLeft(value, "\t\r\n ")
	if trimmed == "" {
		return value
	}
	switch trimmed[0] {
	case '=', '+', '-', '@':
		return "'" + value
	default:
		return value
	}
}
