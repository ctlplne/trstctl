// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/agent/destination"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func (c *IssuerController) reconcileNativeCertificates(ctx context.Context, issuers, clusterIssuers map[string]issuerConfig) (int, error) {
	st, body, err := c.client.request(ctx, http.MethodGet, nativeCertificateCollectionPath(""), nil)
	if err != nil {
		return 0, err
	}
	if st == http.StatusNotFound {
		return 0, nil
	}
	if st/100 != 2 {
		return 0, fmt.Errorf("k8s: list trstctl Certificate resources: status %d: %s", st, string(body))
	}
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return 0, fmt.Errorf("k8s: decode trstctl Certificate list: %w", err)
	}

	issued := 0
	for _, cert := range list.Items {
		didIssue, _, err := c.syncNativeCertificate(ctx, cert, issuers, clusterIssuers, time.Now())
		if err != nil {
			return issued, err
		}
		if didIssue {
			issued++
		}
	}
	return issued, nil
}

// syncNativeCertificate issues one trstctl Certificate into its Secret when it
// has not been issued, its spec changed since it was, its Secret is gone, or
// its renewal time has come (two thirds of the way through the validity it had
// when issued). It returns whether it issued and when it next needs renewing.
func (c *IssuerController) syncNativeCertificate(ctx context.Context, obj map[string]any, issuers, clusterIssuers map[string]issuerConfig, now time.Time) (bool, time.Time, error) {
	namespace := objectNamespace(obj)
	if namespace == "" {
		return false, time.Time{}, nil
	}
	config, backed := c.requestIssuerConfig(obj, issuers, clusterIssuers)
	if !backed {
		return false, time.Time{}, nil
	}
	spec, _ := obj["spec"].(map[string]any)
	if renewAt, current := nativeCertificateCurrent(obj, now); current {
		present, err := c.secretPresent(ctx, namespace, nativeString(spec, "secretName"))
		if err != nil || present {
			return false, renewAt, err
		}
	}
	renewAt, err := c.issueNativeCertificate(ctx, namespace, obj, config)
	return err == nil, renewAt, err
}

// nativeCertificateCurrent reports whether the certificate was issued for its
// present spec and is not yet due for renewal, and when it will be.
func nativeCertificateCurrent(obj map[string]any, now time.Time) (time.Time, bool) {
	if !isReady(obj) {
		return time.Time{}, false
	}
	status, _ := obj["status"].(map[string]any)
	spec, _ := obj["spec"].(map[string]any)
	if stringField(status, "specHash") != nativeSpecHash(spec) {
		return time.Time{}, false
	}
	renewAt, err := time.Parse(time.RFC3339, stringField(status, "renewalTime"))
	if err != nil || !now.Before(renewAt) {
		return time.Time{}, false
	}
	return renewAt, true
}

// nativeSpecHash fingerprints the spec a certificate was issued for, so a
// changed name, key algorithm or Secret reissues it.
func nativeSpecHash(spec map[string]any) string {
	raw, err := json.Marshal(spec)
	if err != nil {
		return ""
	}
	return crypto.SHA256Hex(raw)
}

func (c *IssuerController) secretPresent(ctx context.Context, namespace, name string) (bool, error) {
	if name == "" {
		return false, nil
	}
	st, body, err := c.client.request(ctx, http.MethodGet, NewSecretDestination(c.client, namespace, name).itemPath(), nil)
	secret.Wipe(body)
	if err != nil {
		return false, err
	}
	if st == http.StatusNotFound {
		return false, nil
	}
	if st/100 != 2 {
		return false, fmt.Errorf("k8s: read Secret %s/%s: status %d", namespace, name, st)
	}
	return true, nil
}

func (c *IssuerController) issueNativeCertificate(ctx context.Context, namespace string, obj map[string]any, config issuerConfig) (time.Time, error) {
	name := objectName(obj)
	if name == "" {
		return time.Time{}, permanent(fmt.Errorf("k8s: trstctl Certificate missing metadata.name"))
	}
	spec, _ := obj["spec"].(map[string]any)
	if spec == nil {
		return time.Time{}, permanent(fmt.Errorf("k8s: trstctl Certificate %s missing spec", name))
	}
	secretName := nativeString(spec, "secretName")
	if secretName == "" {
		return time.Time{}, permanent(fmt.Errorf("k8s: trstctl Certificate %s missing spec.secretName", name))
	}
	tmpl, err := nativeCertificateTemplate(spec)
	if err != nil {
		return time.Time{}, permanent(fmt.Errorf("k8s: trstctl Certificate %s: %w", name, err))
	}
	alg, err := nativeKeyAlgorithm(spec)
	if err != nil {
		return time.Time{}, permanent(fmt.Errorf("k8s: trstctl Certificate %s: %w", name, err))
	}

	leafSigner, err := crypto.GenerateLockedKey(alg)
	if err != nil {
		return time.Time{}, fmt.Errorf("k8s: generate key for trstctl Certificate %s: %w", name, err)
	}
	defer leafSigner.Destroy()
	keyDER, err := leafSigner.PKCS8()
	if err != nil {
		return time.Time{}, fmt.Errorf("k8s: export generated key for trstctl Certificate %s: %w", name, err)
	}
	defer secret.Wipe(keyDER)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	defer secret.Wipe(keyPEM)

	csrDER, err := crypto.CreateCertificateRequest(tmpl, leafSigner)
	if err != nil {
		return time.Time{}, fmt.Errorf("k8s: build CSR for trstctl Certificate %s: %w", name, err)
	}
	chainPEM, err := c.signer.Sign(ctx, csrDER, config.limitTTL(defaultCertificateTTL))
	if err != nil {
		return time.Time{}, fmt.Errorf("k8s: sign trstctl Certificate %s: %w", name, err)
	}
	if len(bytes.TrimSpace(chainPEM)) == 0 {
		return time.Time{}, fmt.Errorf("k8s: sign trstctl Certificate %s: empty certificate chain", name)
	}
	leaf, err := certinfo.Inspect(chainPEM)
	if err != nil {
		return time.Time{}, fmt.Errorf("k8s: read issued trstctl Certificate %s: %w", name, err)
	}

	// Renew two thirds of the way through the validity left at issuance. The
	// CA backdates NotBefore for clock skew, so measuring from NotBefore would
	// make a short-lived certificate due the moment it is issued.
	issuedAt := time.Now()
	remaining := leaf.NotAfter.Sub(issuedAt)
	if remaining <= 0 {
		return time.Time{}, fmt.Errorf("k8s: trstctl Certificate %s was issued already expired (notAfter %s)", name, leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	dest := NewSecretDestination(c.client, namespace, secretName)
	if err := dest.Install(ctx, destination.Credential{CertPEM: chainPEM, KeyPEM: keyPEM}); err != nil {
		return time.Time{}, fmt.Errorf("k8s: install trstctl Certificate %s into Secret %s/%s: %w", name, namespace, secretName, err)
	}
	renewAt := issuedAt.Add(remaining * 2 / 3)
	return renewAt, c.markNativeCertificateReady(ctx, namespace, obj, secretName, leaf.NotBefore, leaf.NotAfter, renewAt)
}

func nativeCertificateTemplate(spec map[string]any) (crypto.CertificateRequestTemplate, error) {
	tmpl := crypto.CertificateRequestTemplate{
		CommonName:     nativeString(spec, "commonName"),
		DNSNames:       nativeStringList(spec["dnsNames"]),
		EmailAddresses: nativeStringList(spec["emailAddresses"]),
		URIs:           nativeStringList(spec["uris"]),
	}
	for _, raw := range nativeStringList(spec["ipAddresses"]) {
		ip := net.ParseIP(raw)
		if ip == nil {
			return crypto.CertificateRequestTemplate{}, fmt.Errorf("invalid ipAddresses entry %q", raw)
		}
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	}
	if tmpl.CommonName == "" && len(tmpl.DNSNames) > 0 {
		tmpl.CommonName = tmpl.DNSNames[0]
	}
	if tmpl.CommonName == "" && len(tmpl.DNSNames) == 0 && len(tmpl.IPAddresses) == 0 && len(tmpl.EmailAddresses) == 0 && len(tmpl.URIs) == 0 {
		return crypto.CertificateRequestTemplate{}, fmt.Errorf("spec must include commonName or at least one SAN")
	}
	return tmpl, nil
}

func nativeKeyAlgorithm(spec map[string]any) (crypto.Algorithm, error) {
	raw := nativeString(spec, "keyAlgorithm")
	if raw == "" {
		if pk, _ := spec["privateKey"].(map[string]any); pk != nil {
			raw = nativeString(pk, "algorithm")
		}
	}
	if raw == "" {
		return crypto.ECDSAP256, nil
	}
	alg := crypto.Algorithm(raw)
	switch alg {
	case crypto.RSA2048, crypto.RSA3072, crypto.RSA4096, crypto.ECDSAP256, crypto.ECDSAP384, crypto.ECDSAP521:
		return alg, nil
	default:
		return "", fmt.Errorf("unsupported key algorithm %q", raw)
	}
}

func (c *IssuerController) markNativeCertificateReady(ctx context.Context, namespace string, obj map[string]any, secretName string, notBefore, notAfter, renewAt time.Time) error {
	name := objectName(obj)
	status, _ := obj["status"].(map[string]any)
	if status == nil {
		status = map[string]any{}
	}
	spec, _ := obj["spec"].(map[string]any)
	status["secretName"] = secretName
	status["notBefore"] = notBefore.UTC().Format(time.RFC3339)
	status["notAfter"] = notAfter.UTC().Format(time.RFC3339)
	status["renewalTime"] = renewAt.UTC().Format(time.RFC3339)
	status["specHash"] = nativeSpecHash(spec)
	status["conditions"] = upsertNativeCertificateReady(status["conditions"], secretName)
	obj["status"] = status

	st, body, err := c.client.request(ctx, http.MethodPut, nativeCertificateCollectionPath(namespace)+"/"+name+"/status", obj)
	if err != nil {
		return err
	}
	if st/100 != 2 {
		return fmt.Errorf("k8s: update trstctl Certificate %s/%s status: %d: %s", namespace, name, st, string(body))
	}
	return nil
}

func upsertNativeCertificateReady(existing any, secretName string) []any {
	ready := map[string]any{
		"type":    "Ready",
		"status":  "True",
		"reason":  "Issued",
		"message": "trstctl Certificate issued into Secret " + secretName,
	}
	conds, _ := existing.([]any)
	for i, c := range conds {
		if m, ok := c.(map[string]any); ok && m["type"] == "Ready" {
			conds[i] = ready
			return conds
		}
	}
	return append(conds, ready)
}

func nativeString(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return strings.TrimSpace(v)
}

func nativeStringList(v any) []string {
	switch values := v.(type) {
	case []string:
		out := make([]string, 0, len(values))
		for _, value := range values {
			if value = strings.TrimSpace(value); value != "" {
				out = append(out, value)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(values))
		for _, value := range values {
			if s, ok := value.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	default:
		return nil
	}
}
