// SPDX-License-Identifier: MPL-2.0

// Command trstctl-license is the vendor-side offline license helper.
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/license"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "trstctl-license: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: trstctl-license <gen-key|sign|verify|inspect>")
	}
	switch args[0] {
	case "gen-key":
		return runGenKey(args[1:], stdout)
	case "sign":
		return runSign(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "inspect":
		return runInspect(args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runGenKey(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("gen-key", flag.ContinueOnError)
	privPath := fs.String("private-key", "", "write PEM private key to this path")
	pubPath := fs.String("public-key", "", "write PEM public key to this path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		return err
	}
	if *privPath == "" && *pubPath == "" {
		_, _ = fmt.Fprintf(stdout, "%s%s", priv, pub)
		return nil
	}
	if *privPath == "" || *pubPath == "" {
		return errors.New("gen-key requires both --private-key and --public-key when writing files")
	}
	if err := os.WriteFile(*privPath, priv, 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(*pubPath, pub, 0o644); err != nil { // #nosec G306 -- writes the license PUBLIC key/inspection output; public material (CWE-276)
		return fmt.Errorf("write public key: %w", err)
	}
	_, _ = fmt.Fprintf(stdout, "wrote %s and %s\n", *privPath, *pubPath)
	return nil
}

func runSign(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	privPath := fs.String("private-key", "", "PEM private signing key")
	outPath := fs.String("out", "", "license output path; stdout when empty")
	id := fs.String("id", "", "license id")
	customer := fs.String("customer", "", "customer name")
	tier := fs.String("tier", "", "enterprise or provider")
	features := fs.String("features", "", "comma-separated explicit feature extras")
	managedCustomerBand := fs.Int("managed-customer-band", 0, "Provider/MSP contracted managed-customer band; zero means negotiated or unlimited")
	tenantBand := fs.Int("tenant-band", 0, "deprecated alias for --managed-customer-band")
	productionDeploymentID := fs.String("production-deployment-id", "", "stable ID of the one licensed production control plane")
	nonProductionDeploymentIDs := fs.String("non-production-deployment-ids", "", "comma-separated stable IDs for up to three bundled non-production control planes")
	issuedAt := fs.String("issued-at", time.Now().UTC().Format(time.RFC3339), "RFC3339 issue time")
	expiresAt := fs.String("expires-at", "", "RFC3339 expiry time")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *privPath == "" || *id == "" || *customer == "" || *tier == "" || *expiresAt == "" || *productionDeploymentID == "" {
		return errors.New("sign requires --private-key, --id, --customer, --tier, --production-deployment-id, and --expires-at")
	}
	provided := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { provided[f.Name] = true })
	if provided["managed-customer-band"] && provided["tenant-band"] {
		return errors.New("sign accepts only one of --managed-customer-band and deprecated --tenant-band")
	}
	band := *managedCustomerBand
	if provided["tenant-band"] {
		band = *tenantBand
	}
	licenseTier := license.Tier(*tier)
	if licenseTier != license.TierEnterprise && licenseTier != license.TierProvider {
		return fmt.Errorf("sign: tier must be enterprise or provider, got %q", *tier)
	}
	if band < 0 {
		return errors.New("sign: managed customer band cannot be negative")
	}
	if licenseTier != license.TierProvider && band != 0 {
		return errors.New("sign: --managed-customer-band is only valid for provider licenses")
	}
	issued, err := time.Parse(time.RFC3339, *issuedAt)
	if err != nil {
		return fmt.Errorf("parse --issued-at: %w", err)
	}
	expires, err := time.Parse(time.RFC3339, *expiresAt)
	if err != nil {
		return fmt.Errorf("parse --expires-at: %w", err)
	}
	priv, err := os.ReadFile(*privPath)
	if err != nil {
		return fmt.Errorf("read private key: %w", err)
	}
	claims := license.Claims{
		V: 2, ID: *id, Customer: *customer, Tier: licenseTier,
		Features: parseFeatures(*features), TenantBand: band,
		DeploymentEntitlement: &license.DeploymentEntitlement{
			ProductionDeploymentID:     *productionDeploymentID,
			NonProductionDeploymentIDs: parseDeploymentIDs(*nonProductionDeploymentIDs),
			NonProductionAllowance:     license.BundledNonProductionDeployments,
		},
		IssuedAt: issued, ExpiresAt: expires,
	}
	if err := license.ValidateClaims(claims); err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	raw, err := license.Sign(claims, priv)
	if err != nil {
		return err
	}
	if *outPath == "" {
		_, _ = stdout.Write(raw)
		_, _ = io.WriteString(stdout, "\n")
		return nil
	}
	return os.WriteFile(*outPath, raw, 0o644) // #nosec G306 G703 -- writes the license PUBLIC key/inspection output; public material (CWE-22, CWE-276)
}

func runVerify(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	licensePath := fs.String("license", "", "license file")
	pubPath := fs.String("public-key", "", "trusted PEM public key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *licensePath == "" || *pubPath == "" {
		return errors.New("verify requires --license and --public-key")
	}
	raw, err := os.ReadFile(*licensePath)
	if err != nil {
		return fmt.Errorf("read license: %w", err)
	}
	pub, err := os.ReadFile(*pubPath)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	claims, err := license.Verify(raw, [][]byte{pub})
	if err != nil {
		return err
	}
	productionID := "legacy-unbound"
	nonProductionCount := 0
	if claims.DeploymentEntitlement != nil {
		productionID = claims.DeploymentEntitlement.ProductionDeploymentID
		nonProductionCount = len(claims.DeploymentEntitlement.NonProductionDeploymentIDs)
	}
	_, _ = fmt.Fprintf(stdout, "ok: %s %s %s v%d expires %s managed_customer_band=%d production_deployment_id=%s non_production_deployments=%d/%d rights=%s\n", claims.ID, claims.Customer, claims.Tier, claims.V, claims.ExpiresAt.Format(time.RFC3339), claims.TenantBand, productionID, nonProductionCount, license.BundledNonProductionDeployments, joinRights(license.TierRights(claims.Tier)))
	return nil
}

func runInspect(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	licensePath := fs.String("license", "", "license file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *licensePath == "" {
		return errors.New("inspect requires --license")
	}
	raw, err := os.ReadFile(*licensePath)
	if err != nil {
		return fmt.Errorf("read license: %w", err)
	}
	claims, err := inspectClaims(raw)
	if err != nil {
		return err
	}
	pretty, err := json.MarshalIndent(struct {
		license.Claims
		ManagedCustomerBand int             `json:"managed_customer_band,omitempty"`
		Rights              []license.Right `json:"rights"`
	}{
		Claims:              claims,
		ManagedCustomerBand: claims.TenantBand,
		Rights:              license.TierRights(claims.Tier),
	}, "", "  ")
	if err != nil {
		return err
	}
	_, _ = stdout.Write(pretty)
	_, _ = io.WriteString(stdout, "\n")
	return nil
}

func joinRights(rights []license.Right) string {
	parts := make([]string, 0, len(rights))
	for _, right := range rights {
		parts = append(parts, string(right))
	}
	return strings.Join(parts, ",")
}

func parseFeatures(raw string) []license.Feature {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]license.Feature, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, license.Feature(part))
		}
	}
	return out
}

func parseDeploymentIDs(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if id := strings.TrimSpace(part); id != "" {
			out = append(out, id)
		}
	}
	return out
}

func inspectClaims(raw []byte) (license.Claims, error) {
	var file license.File
	if err := json.Unmarshal(raw, &file); err != nil {
		return license.Claims{}, fmt.Errorf("malformed license file: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(file.Payload)
	if err != nil {
		return license.Claims{}, fmt.Errorf("malformed payload encoding: %w", err)
	}
	var claims license.Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return license.Claims{}, fmt.Errorf("malformed claims: %w", err)
	}
	return claims, nil
}
