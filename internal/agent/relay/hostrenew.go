// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/custody"
)

// Host-generated renewal: the key is born here and dies here (epic B2).
//
// Every other job kind in this package RECEIVES material. This one MAKES it,
// and that inversion is the entire epic: a private key generated on the machine
// that will serve it never crosses the network, never rests in an outbox row,
// and never enters the tenant's append-only event log — because it never exists
// anywhere the control plane can see.
//
// What travels up is a CSR. What comes back is a certificate. Neither can carry
// a private key, so the property does not depend on anyone remembering to keep
// it: there is no field to put a key in.
//
// The failure discipline is the same one D1 and D2 established. This code does
// three things in order — generate, get signed, install — and each has its own
// failure that must be reported as itself. A renewal that got a certificate and
// could not install it is a very different situation from one that never got a
// certificate, and collapsing them into "failed" sends an operator to the wrong
// machine.

// KindEndpointRenew is the host-generated renewal kind (epic B2).
const KindEndpointRenew = "endpoint.renew"

// CSRSigner is the control-plane call that turns a locally generated CSR into a
// certificate.
//
// It is a SEPARATE interface from Channel rather than another method on it. A
// relay that cannot generate host keys — a network relay driving an appliance —
// has no use for this call and should not be made to implement it to satisfy a
// compiler. A channel that does not implement it simply cannot take renewal
// work, and says so, which is exactly the right behavior for a build that
// predates the RPC.
type CSRSigner interface {
	SignJobCSR(ctx context.Context, jobID int64, attempt int, csrDER []byte) (certPEM, chainPEM []byte, fingerprint string, err error)
}

// runHostRenew generates a key, gets a certificate for it, installs both, and
// verifies the result.
func runHostRenew(ctx context.Context, ch Channel, client *http.Client, profile connector.LocalOpsConfig, hostRollback *HostRollbackStore, job Job) bool {
	var intent DeployIntent
	if err := decodeIntent(job.Payload, &intent); err != nil {
		report(ctx, ch, job, OutcomeFailed, "job payload is not a renewal intent")
		return false
	}

	signer, ok := ch.(CSRSigner)
	if !ok {
		// Refused before generating anything. A key generated for a certificate
		// that can never be requested is pure liability: material on disk-adjacent
		// memory with no purpose and no consumer.
		report(ctx, ch, job, OutcomeFailed,
			"this agent build cannot request signing for a locally generated key")
		return false
	}
	custodyReporter, ok := ch.(CustodyReceiptChannel)
	if !ok {
		report(ctx, ch, job, OutcomeFailed,
			"this agent build cannot sign certificate custody receipts")
		return false
	}
	if !ExecutesOnHost(intent.Connector) {
		// B2 is host-only by construction. A relay generating a key for an
		// appliance it merely reaches would rebuild the custody hop this epic
		// removes, with one more machine in the chain rather than one fewer.
		report(ctx, ch, job, OutcomeFailed,
			"host-generated renewal requires a host-executable connector")
		return false
	}
	if RequiresHostExecProfile(intent.Connector) && len(profile.AllowedRoots) == 0 {
		report(ctx, ch, job, OutcomeFailed,
			"this agent has no host exec profile configured for file and reload deploys")
		return false
	}

	names := renewalSubjectNames(intent)
	if len(names) == 0 {
		report(ctx, ch, job, OutcomeFailed, "renewal intent names no subject to certify")
		return false
	}
	var claim *hostRenewClaim
	if maintainer, ok := ch.(JobLeaseMaintainer); ok {
		var err error
		claim, err = maintainHostRenewClaim(ctx, maintainer, job)
		if err != nil {
			report(ctx, ch, job, OutcomeFailed, "the host renewal job claim could not be maintained")
			return false
		}
		defer claim.stop()
		ctx = claim.ctx
	}
	management, destroyManagement, err := redeemHostManagement(ctx, ch, job, intent.CredentialRefs)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "host management credentials were not available for this attempt")
		return false
	}
	defer destroyManagement()
	if intent.Connector == "java-keystore" {
		// Prove the password format and local reload authority before minting
		// another certificate. A changed host profile must fail before signing.
		if err := preflightJavaRenewal(profile, intent, management); err != nil {
			report(ctx, ch, job, OutcomeFailed, "Java keystore preparation failed before signing: "+err.Error())
			return false
		}
	}

	key, err := generateHostRenewSubjectKey(intent)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "a subject key could not be generated on this host")
		return false
	}
	// The key's life ends here on EVERY path out, including a panic inside a
	// connector. This defer is the load-bearing line of the file: it is what
	// makes "the private half never outlives the deploy" a property of the code
	// rather than a claim in a document.
	defer key.Destroy()

	certPEM, chainPEM, fingerprint, err := signHostCSR(ctx, signer, job, key.CSRDER, claim != nil)
	if err != nil {
		// The control plane holds the reason — a name outside the binding, a
		// profile refusal, a lapsed lease — and has already recorded it.
		// Guessing here would put a second, less accurate account into the
		// tenant's history alongside the accurate one.
		report(ctx, ch, job, OutcomeFailed, "the control plane did not sign this host's request")
		return false
	}
	if len(certPEM) == 0 {
		report(ctx, ch, job, OutcomeFailed, "signing returned no certificate")
		return false
	}
	if claim != nil {
		if err := claim.confirm(); err != nil {
			report(ctx, ch, job, OutcomeFailed, "the host renewal job claim was lost before installation")
			return false
		}
	}
	if ctx.Err() != nil {
		return false
	}

	exported, err := key.PrivateKeyPEM()
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "the generated key could not be exported for installation")
		return false
	}
	// The exported PEM goes straight into a LOCKED buffer (AN-8), the same
	// custody the redeemed-credential path gives appliance secrets in
	// AdoptMaterial.
	//
	// PrivateKeyPEM hands back ordinary heap memory — pem.EncodeToMemory
	// allocates a plain []byte — so without this the private half of a key this
	// epic exists to protect would spend its life swappable and dumpable, while
	// every other secret the agent handles sits in mlock'd, MADV_DONTDUMP
	// pages. The window is short, but "short" is not a memory-protection
	// property, and a host that swaps during a deploy writes the key to disk.
	keyBuf, err := secret.NewFrom(exported)
	secret.Wipe(exported)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "the generated key could not be moved into locked memory")
		return false
	}
	defer keyBuf.Destroy()
	keyPEM := keyBuf.Bytes()

	material := Material{
		"credential.cert_pem": certPEM,
		"credential.key_pem":  keyPEM,
	}
	for ref, value := range management {
		material[ref] = value
	}
	if len(chainPEM) > 0 {
		material["credential.chain_pem"] = chainPEM
	}

	// The fingerprint the control plane reported is what the deploy records and
	// what verification compares against. Taking it from the response rather
	// than re-deriving it locally means an agent cannot report a deploy of a
	// certificate other than the one that was issued to it.
	installIntent := intent
	if fingerprint != "" {
		installIntent.Fingerprint = fingerprint
	}

	if _, err := ExecuteOnHost(ctx, profile, installIntent, material, client); err != nil {
		// Reached only after a certificate was successfully issued. Naming that
		// matters: the identity now has a live certificate the estate is not
		// serving, which is a different repair than "renewal failed".
		report(ctx, ch, job, OutcomeFailed,
			"a certificate was issued for this host but could not be installed")
		return false
	}
	if intent.MigrationRunID != "" && hostRollback == nil {
		report(ctx, ch, job, OutcomeFailed,
			"migration renewal cannot retain its local predecessor for rollback")
		return false
	}
	if hostRollback != nil {
		if strings.TrimSpace(intent.TargetID) == "" || strings.TrimSpace(fingerprint) == "" {
			report(ctx, ch, job, OutcomeFailed,
				"host renewal is missing target or fingerprint rollback identity")
			return false
		}
		servingCertPEM, servingErr := servingCertificatePEM(material)
		if servingErr != nil {
			report(ctx, ch, job, OutcomeFailed, "host predecessor state could not be assembled")
			return false
		}
		if err := hostRollback.RecordDeploy(intent.Connector, intent.TargetID, fingerprint, servingCertPEM, keyPEM); err != nil {
			report(ctx, ch, job, OutcomeFailed, "host predecessor state could not be committed")
			return false
		}
	}

	// D2's post-deploy handshake, unchanged. A renewal that installed and does
	// not serve is not a success, and the whole reason this pipeline reports
	// three outcomes rather than two is so it can say which happened.
	outcome, detail, evidence := postDeployVerificationWithNative(ctx, installIntent, material, profile.TLSProbeOpenSSL)
	record, err := HostRenewCustody(intent.Connector, "")
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "the installed key custody could not be classified")
		return false
	}
	reportWithEvidenceAndCustody(ctx, custodyReporter, job, outcome, detail, evidence, fingerprint, record)
	return outcome != OutcomeFailed
}

// HostRenewCustody maps a host connector to the storage boundary it actually
// uses after a successful deploy. The caller supplies generatedBy when it knows
// the certificate identity; the relay runtime leaves it empty and the channel
// adapter fills it from the same mTLS identity that signs the receipt.
func HostRenewCustody(connectorName, generatedBy string) (custody.Record, error) {
	if !ExecutesOnHost(connectorName) {
		return custody.Record{}, errors.New("relay: connector is not a host renewal target")
	}
	record := custody.Record{Origin: custody.OriginHostAgent, GeneratedBy: generatedBy}
	switch connectorName {
	case "iis":
		record.Storage = custody.StorageOSStore
		record.Exportable = custody.NonExportable
	case "envoy":
		record.Storage = custody.StorageService
		record.Exportable = custody.Exportable
	default:
		record.Storage = custody.StorageFile
		record.Exportable = custody.Exportable
	}
	return record, nil
}

// renewalSubjectNames is the set the intent asks to certify.
//
// Advisory only on this side. The control plane re-derives the authorized set
// from the job payload it queued and refuses anything outside it, so this check
// exists to fail fast and locally rather than to be the gate — an agent cannot
// widen its own authorization by editing this function.
func renewalSubjectNames(intent DeployIntent) []string {
	out := make([]string, 0, len(intent.SubjectDNSNames)+1)
	seen := map[string]bool{}
	add := func(n string) {
		n = strings.TrimSpace(n)
		if n == "" || seen[strings.ToLower(n)] {
			return
		}
		seen[strings.ToLower(n)] = true
		out = append(out, n)
	}
	for _, n := range intent.SubjectDNSNames {
		add(n)
	}
	add(intent.SubjectCommonName)
	return out
}
