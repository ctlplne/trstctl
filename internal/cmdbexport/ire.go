// SPDX-License-Identifier: BUSL-1.1
// Package cmdbexport builds the one supported CMDB write contract: certificate
// CIs through ServiceNow IRE. It owns no credentials and sends no requests.
package cmdbexport

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/certinfo"
)

const CertificateClass = "cmdb_ci_certificate"

type Source struct {
	Name       string `json:"source_name"`
	Key        string `json:"source_native_key"`
	ObservedAt string `json:"source_recency_timestamp"`
}
type Item struct {
	ClassName string            `json:"className"`
	Values    map[string]string `json:"values"`
	Source    Source            `json:"sys_object_source_info"`
}
type Request struct {
	Items []Item `json:"items"`
}

// Endpoint fixes the IRE path; tenant input cannot name a table. Source is an
// operator-registered discovery_source choice on the ServiceNow instance.
func Endpoint(instance, source string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(instance))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("CMDB export needs an HTTPS instance origin without credentials, path, query or fragment")
	}
	source = strings.TrimSpace(source)
	if source == "" || len(source) > 128 {
		return "", fmt.Errorf("CMDB export needs the operator-registered source name (1-128 bytes)")
	}
	u.Path = "/api/now/identifyreconcile"
	q := url.Values{}
	q.Set("sysparm_data_source", source)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// Payload maps only observed certificate metadata. In particular issuer and
// root_issuer are references, so a DN must never be placed into either field.
func Payload(tenant, source string, info certinfo.Info, status string, observed time.Time) (Request, error) {
	tenant = strings.TrimSpace(tenant)
	source = strings.TrimSpace(source)
	if tenant == "" || source == "" || !fingerprint(info.SHA256Fingerprint) {
		return Request{}, fmt.Errorf("CMDB export needs tenant, registered source and a SHA-256 certificate fingerprint")
	}
	state := ""
	switch status {
	case "active":
		state = "issued"
	case "revoked":
		state = "revoked"
	case "superseded":
		state = "retired"
	default:
		return Request{}, fmt.Errorf("unsupported certificate lifecycle state %q", status)
	}
	if info.NotBefore.IsZero() || info.NotAfter.Before(info.NotBefore) {
		return Request{}, fmt.Errorf("certificate validity is missing or reversed")
	}
	name := info.CommonName
	if name == "" {
		name = info.Subject
	}
	if name == "" {
		name = info.SHA256Fingerprint
	}
	values := map[string]string{
		"name": name, "fingerprint": info.SHA256Fingerprint, "fingerprint_algorithm": "SHA256",
		"serial_number": info.SerialNumber, "subject_common_name": info.CommonName,
		"subject_distinguished_name": info.Subject, "issuer_distinguished_name": info.Issuer,
		"valid_from": info.NotBefore.UTC().Format("2006-01-02 15:04:05"), "valid_to": info.NotAfter.UTC().Format("2006-01-02 15:04:05"),
		"signature_algorithm": info.SignatureAlgorithm, "state": state, "discovery_source": source,
	}
	if info.PublicKeyBits > 0 {
		values["key_size"] = strconv.Itoa(info.PublicKeyBits)
	}
	return Request{Items: []Item{{ClassName: CertificateClass, Values: values, Source: Source{Name: source, Key: tenant + ":" + info.SHA256Fingerprint, ObservedAt: observed.UTC().Format("2006-01-02 15:04:05")}}}}, nil
}

func fingerprint(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
