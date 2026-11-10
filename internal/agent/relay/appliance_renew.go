// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/custody"
)

// Appliance-generated renewal (A122).
//
// The same endpoint.renew job a host agent runs, for an appliance target that
// declared key_generation=appliance and pinned a network relay. The relay
// generates nothing: it asks the appliance to generate the key and a CSR, has
// the control plane sign the CSR, and installs the certificate against the key
// the appliance holds. No key crosses this process, so there is no pending key
// to retain across a crash — a reclaimed job asks the appliance again and gets
// the same CSR back from the object named for the job.

// ApplianceReferenceRecorder keeps an appliance's own reference for a job's
// key request on the control plane (A122). An appliance that names its
// requests itself (Cisco ISE's CSR IDs) cannot be asked for "the request named
// for this job"; recording its ID before the signature is requested is what
// lets every later attempt of the job reuse that request. A refusal means the
// claim is gone.
type ApplianceReferenceRecorder interface {
	RecordJobApplianceReference(ctx context.Context, jobID int64, attempt int, reference string) error
}

// ApplianceRenewCustody is the custody an appliance-generated key records: made
// on the appliance, kept in its own key store, and exportable by an
// administrator of the appliance, because the keys this mode creates are
// software keys (a NetScaler or A10 key file, an F5 key without FIPS, a PAN-OS
// key without an HSM, an ISE system certificate key). GeneratedBy names the agent that asked for it.
func ApplianceRenewCustody(generatedBy string) custody.Record {
	return custody.Record{
		Origin: custody.OriginAppliance, Storage: custody.StorageAppliance,
		Exportable: custody.Exportable, GeneratedBy: generatedBy,
	}
}

// runApplianceRenew asks the appliance for a key and CSR, gets the CSR signed,
// installs the certificate against the appliance's key, and reports what the
// listener and the appliance then serve.
func runApplianceRenew(ctx context.Context, ch Channel, client *http.Client, job Job, intent DeployIntent) bool {
	signer, ok := ch.(CSRSigner)
	if !ok {
		report(ctx, ch, job, OutcomeFailed, "this agent build cannot request signing for an appliance-generated key")
		return false
	}
	custodyReporter, ok := ch.(CustodyReceiptChannel)
	if !ok {
		report(ctx, ch, job, OutcomeFailed, "this agent build cannot sign certificate custody receipts")
		return false
	}
	if !connector.ApplianceKeyFamily(intent.Connector) || !Executes(intent.Connector) {
		report(ctx, ch, job, OutcomeFailed, "this connector cannot generate its key on the appliance")
		return false
	}
	if len(intent.SubjectEmailAddresses) > 0 || len(intent.SubjectURIs) > 0 {
		report(ctx, ch, job, OutcomeFailed, "an appliance-generated key certifies DNS names and IP addresses only")
		return false
	}
	if len(renewalSubjectNames(intent)) == 0 {
		report(ctx, ch, job, OutcomeFailed, "renewal intent names no subject to certify")
		return false
	}
	object := connector.ApplianceKeyObjectName(intent.TargetID, job.JobID)
	var target TargetConfig
	if len(intent.TargetConfig) > 0 {
		if err := json.Unmarshal(intent.TargetConfig, &target); err != nil {
			report(ctx, ch, job, OutcomeFailed, "the appliance target configuration did not decode")
			return false
		}
	}
	if object == "" || strings.TrimSpace(target.Endpoint) == "" {
		report(ctx, ch, job, OutcomeFailed, "the appliance renewal names no target or management endpoint")
		return false
	}

	var claim *hostRenewClaim
	if maintainer, ok := ch.(JobLeaseMaintainer); ok {
		var err error
		claim, err = maintainHostRenewClaim(ctx, maintainer, job)
		if err != nil {
			report(ctx, ch, job, OutcomeFailed, "the appliance renewal job claim could not be maintained")
			return false
		}
		defer claim.stop()
		ctx = claim.ctx
	}
	management, destroyManagement, err := redeemHostManagement(ctx, ch, job, intent.CredentialRefs)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "appliance management credentials were not available for this attempt")
		return false
	}
	defer destroyManagement()
	built, err := buildRelayConnector(intent.Connector, target, management)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "the appliance connector could not be built: "+strings.TrimPrefix(err.Error(), "relay: "))
		return false
	}
	if closer, ok := built.(interface{ Close() }); ok {
		defer closer.Close()
	}
	ops := connector.NewHTTPOps(client)

	key, stats, err := connector.RunApplianceKey(ctx, built, ops, connector.ApplianceKeyRequest{
		ObjectName: object, CommonName: intent.SubjectCommonName,
		DNSNames: intent.SubjectDNSNames, IPAddresses: intent.SubjectIPAddresses,
		Reference: job.ApplianceReference,
	})
	if stats.Denied > 0 {
		report(ctx, ch, job, OutcomeFailed, "connector attempted an operation outside its declared capabilities")
		return false
	}
	var (
		certPEM, chainPEM []byte
		fingerprint       string
		installed         *connector.ApplianceKeyInstalledError
	)
	switch {
	case errors.As(err, &installed) && len(installed.CertificatePEM) > 0:
		// PANOS-O1: an earlier attempt imported this job's certificate and
		// the appliance kept no request to sign again. Finish with the job's
		// own signed result instead of stopping.
		var ok bool
		if certPEM, chainPEM, fingerprint, ok = recoverInstalledApplianceCertificate(ctx, ch, job, object, installed, claim != nil); !ok {
			return false
		}
		key = connector.ApplianceKey{ObjectName: object}
	case errors.Is(err, connector.ErrApplianceKeyAlreadyInstalled):
		report(ctx, ch, job, OutcomeFailed, "an earlier attempt of this renewal already installed its certificate against the "+
			"appliance key, and the appliance kept no request to sign again; check the appliance and start a new renewal")
		return false
	case err != nil:
		log.Printf("trstctl-agent: job %d attempt %d: appliance key generation failed: %v", job.JobID, job.Attempt, err)
		report(ctx, ch, job, OutcomeFailed, "the appliance did not generate a key and CSR")
		return false
	default:
		var ok bool
		if certPEM, chainPEM, fingerprint, ok = signApplianceRequest(ctx, ch, signer, job, key, claim != nil); !ok {
			return false
		}
	}
	if claim != nil {
		if err := claim.confirm(); err != nil {
			report(ctx, ch, job, OutcomeFailed, "the appliance renewal job claim was lost before installation")
			return false
		}
	}
	if ctx.Err() != nil {
		return false
	}

	material := Material{"credential.cert_pem": certPEM}
	if len(chainPEM) > 0 {
		material["credential.chain_pem"] = chainPEM
	}
	servingPEM, err := servingCertificatePEM(material)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "the issued certificate could not be assembled for installation")
		return false
	}
	installIntent := intent
	installIntent.Fingerprint = fingerprint
	stats, err = connector.RunApplianceInstall(ctx, built, ops, connector.Deployment{
		Target: intent.Target, CertPEM: servingPEM, Fingerprint: fingerprint,
	}, key)
	if stats.Denied > 0 {
		report(ctx, ch, job, OutcomeFailed, "connector attempted an operation outside its declared capabilities")
		return false
	}
	if err != nil {
		// Reached only after a certificate was issued: the identity has a live
		// certificate the appliance is not serving, which is a different repair
		// than a refused renewal. The device error stays in this machine's log.
		log.Printf("trstctl-agent: job %d attempt %d: appliance install of the issued certificate failed: %v", job.JobID, job.Attempt, err)
		report(ctx, ch, job, OutcomeFailed, "the certificate was issued but the appliance did not install it against its key")
		return false
	}

	outcome, detail, evidence := postDeployVerification(ctx, installIntent, material)
	if verdict, readback := applianceReadback(ctx, client, installIntent, management); readback != "" {
		detail = withApplianceReadback(detail, verdict, readback)
		if !readbackConfirms(verdict) && outcome == transport.OutcomeVerified {
			outcome = transport.OutcomeVerifyFailed
		}
	}
	accepted, reportErr := custodyReporter.ReportJobResultWithCustody(ctx, job.JobID, job.Attempt,
		outcome, detail, evidence, fingerprint, ApplianceRenewCustody(""))
	logReportOutcome(job, outcome, accepted, reportErr)
	return outcome != OutcomeFailed && outcome != transport.OutcomeVerifyFailed
}

// signApplianceRequest has the control plane sign the CSR the appliance
// returned, after keeping the appliance's own request ID for the job when it
// named one. ok is false once the failure has been reported.
func signApplianceRequest(ctx context.Context, ch Channel, signer CSRSigner, job Job, key connector.ApplianceKey, maintained bool) ([]byte, []byte, string, bool) {
	if ref := strings.TrimSpace(key.Reference); ref != "" && ref != job.ApplianceReference {
		// The appliance named a new request (Cisco ISE's CSR ID). Keep it for
		// the job before asking for a signature, so a later attempt reuses
		// this request instead of making another.
		recorder, ok := ch.(ApplianceReferenceRecorder)
		if !ok {
			report(ctx, ch, job, OutcomeFailed, "this agent build cannot keep the appliance's request ID for the renewal")
			return nil, nil, "", false
		}
		if err := recorder.RecordJobApplianceReference(ctx, job.JobID, job.Attempt, ref); err != nil {
			report(ctx, ch, job, OutcomeFailed, "the appliance's request ID could not be kept for this renewal; nothing was signed")
			return nil, nil, "", false
		}
	}
	block, _ := pem.Decode(key.CSRPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		report(ctx, ch, job, OutcomeFailed, "the appliance returned no certificate request")
		return nil, nil, "", false
	}
	certPEM, chainPEM, fingerprint, err := signHostCSR(ctx, signer, job, block.Bytes, maintained)
	if err != nil {
		if transport.IsCSRValidityRefusal(err) {
			report(ctx, ch, job, OutcomeFailed, transport.CSRValidityRefusalDetail)
			return nil, nil, "", false
		}
		report(ctx, ch, job, OutcomeFailed, "the control plane did not sign the appliance's request")
		return nil, nil, "", false
	}
	if len(certPEM) == 0 {
		report(ctx, ch, job, OutcomeFailed, "signing returned no certificate")
		return nil, nil, "", false
	}
	return certPEM, chainPEM, fingerprint, true
}

// JobCertificateRecoverer hands a reclaimed job back the certificate the
// control plane already signed for it, named by the certificate its
// appliance installed (PANOS-O1). The control plane answers only when its
// signed result for the job is exactly that certificate.
type JobCertificateRecoverer interface {
	RecoverJobCertificate(ctx context.Context, jobID int64, attempt int, installedDER []byte) (certPEM, chainPEM []byte, fingerprint string, err error)
}

// recoverInstalledApplianceCertificate gets the job's signed result for the
// certificate an earlier attempt already imported into the job's object, and
// checks it is that certificate. ok is false once the failure has been
// reported.
func recoverInstalledApplianceCertificate(ctx context.Context, ch Channel, job Job, object string,
	installed *connector.ApplianceKeyInstalledError, maintained bool) ([]byte, []byte, string, bool) {
	recoverer, ok := ch.(JobCertificateRecoverer)
	if !ok {
		report(ctx, ch, job, OutcomeFailed, "an earlier attempt of this renewal already installed its certificate, and this "+
			"agent build cannot ask for the job's signed result to finish it; start a new renewal")
		return nil, nil, "", false
	}
	block, _ := pem.Decode(installed.CertificatePEM)
	if installed.ObjectName != object || block == nil || block.Type != "CERTIFICATE" {
		report(ctx, ch, job, OutcomeFailed, "the appliance's object for this renewal holds no readable certificate")
		return nil, nil, "", false
	}
	certPEM, chainPEM, fingerprint, err := callJobSigner(ctx, maintained, func(callCtx context.Context) ([]byte, []byte, string, error) {
		return recoverer.RecoverJobCertificate(callCtx, job.JobID, job.Attempt, block.Bytes)
	})
	if err != nil {
		log.Printf("trstctl-agent: job %d attempt %d: the job's signed result was not handed back: %v", job.JobID, job.Attempt, err)
		report(ctx, ch, job, OutcomeFailed, "an earlier attempt of this renewal already installed a certificate, and the "+
			"control plane did not hand it back as this job's signed result; check the appliance and start a new renewal")
		return nil, nil, "", false
	}
	if returned, _ := pem.Decode(certPEM); returned == nil || !bytes.Equal(returned.Bytes, block.Bytes) {
		report(ctx, ch, job, OutcomeFailed, "the control plane handed back a certificate other than the one the appliance holds")
		return nil, nil, "", false
	}
	return certPEM, chainPEM, fingerprint, true
}
