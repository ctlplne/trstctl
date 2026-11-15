// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/kms/tpm"
)

// runHostReprotect has a separate subject-key path from ordinary renewal: the
// signer receives a CSR made by the installed key, never a newly generated key.
// The encrypted job slot holds one CSR and result across claim recovery.
func runHostReprotect(ctx context.Context, ch Channel, client *http.Client, profile connector.LocalOpsConfig,
	rollback *HostRollbackStore, job Job, intent DeployIntent) bool {
	signer, signs := ch.(CSRSigner)
	reporter, reports := ch.(CustodyReceiptChannel)
	if !signs || !reports || rollback == nil || !ExecutesOnHost(intent.Connector) ||
		(RequiresHostExecProfile(intent.Connector) && len(profile.AllowedRoots) == 0) {
		report(ctx, ch, job, OutcomeFailed, "CA re-protection needs a host signer, signed custody receipt, local profile and rollback store")
		return false
	}
	if intent.PQCRunID != "" || intent.MigrationRunID != "" || intent.ReprotectJobID == "" ||
		intent.ReprotectPredecessorFingerprint == "" || intent.ReprotectPredecessorSPKISHA256 == "" ||
		intent.PredecessorCertificateID == "" || intent.IdentityID == "" || intent.IssuingAuthoritySource != "private" ||
		intent.IssuingAuthorityID == "" || (len(intent.SubjectDNSNames) == 0 && len(intent.SubjectIPAddresses) == 0 && len(intent.SubjectEmailAddresses) == 0 && len(intent.SubjectURIs) == 0) ||
		intent.VerifyAddress == "" || intent.VerifyServerName == "" {
		report(ctx, ch, job, OutcomeFailed, "CA re-protection intent is incomplete or mixed with another migration")
		return false
	}
	var claim *hostRenewClaim
	if maintainer, ok := ch.(JobLeaseMaintainer); ok {
		var err error
		claim, err = maintainHostRenewClaim(ctx, maintainer, job)
		if err != nil {
			report(ctx, ch, job, OutcomeFailed, "CA re-protection job claim could not be maintained")
			return false
		}
		defer claim.stop()
		ctx = claim.ctx
	}
	// TPM-O1-L1: a TPM-held predecessor key is a TSS2 key file only this
	// host's TPM can load. The TPM signs the re-protected CSR and certifies
	// the key again under its attestation key, and the control plane signs
	// only that attested CSR; no software key is made or read.
	tpmHeld := intent.KeyCustody == HostKeyCustodyTPM
	var hostTPM *hostKeyTPM
	defer func() { hostTPM.Close() }()
	if tpmHeld {
		if refusal := tpmHostKeyRefusal(ch, profile, intent); refusal != "" {
			report(ctx, ch, job, OutcomeFailed, refusal)
			return false
		}
		opened, err := openHostKeyTPM(*profile.HostKeyTPM)
		if err != nil {
			log.Printf("trstctl-agent: job %d attempt %d: host key TPM: %v", job.JobID, job.Attempt, err)
			report(ctx, ch, job, OutcomeFailed, "this host's TPM could not be opened for the CA re-protection")
			return false
		}
		hostTPM = opened
	} else if intent.KeyCustody != "" {
		report(ctx, ch, job, OutcomeFailed, "the CA re-protection asks for key custody "+fmt.Sprintf("%q", intent.KeyCustody)+", which this agent does not provide")
		return false
	}
	management, destroyManagement, err := redeemHostManagement(ctx, ch, job, intent.CredentialRefs)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "host management credentials were unavailable")
		return false
	}
	defer destroyManagement()
	keyMatches := crypto.VerifyCertKeyMatchPEM
	if tpmHeld {
		keyMatches = func(certPEM, keyFile []byte) error {
			info, err := certinfo.Inspect(certPEM)
			if err != nil {
				return err
			}
			return tpmKeyFileMatches(hostTPM, keyFile, info.SPKISHA256)
		}
	}
	if err := adoptReprotectPredecessor(ctx, profile, rollback, intent, keyMatches); err != nil {
		report(ctx, ch, job, OutcomeFailed, "CA predecessor could not be pinned and independently verified: "+err.Error())
		return false
	}
	pending, err := rollback.LoadReprotectPending(intent.Connector, intent.TargetID, intent.ReprotectJobID)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "CA re-protection pending CSR could not be recovered")
		return false
	}
	defer wipeReprotectPending(pending)
	var csrDER, certPEM, chainPEM []byte
	var fingerprint string
	if pending != nil {
		csrDER, certPEM, chainPEM, fingerprint = pending.CSRDER, pending.CertPEM, pending.ChainPEM, pending.Fingerprint
	} else {
		err = rollback.UseReprotectPredecessor(intent.Connector, intent.TargetID, intent.ReprotectJobID,
			intent.ReprotectPredecessorFingerprint, func(_, keyPEM []byte) error {
				tmpl, createErr := hostSubjectTemplate(intent)
				if createErr != nil {
					return createErr
				}
				if tpmHeld {
					csrDER, createErr = createTPMRetainedHostKeyCSR(hostTPM, keyPEM, tmpl, intent.ReprotectPredecessorSPKISHA256)
					return createErr
				}
				csrDER, createErr = crypto.CreateRetainedHostKeyCSRFromTemplate(keyPEM, tmpl, intent.ReprotectPredecessorSPKISHA256)
				return createErr
			})
		if err == nil {
			err = rollback.RecordReprotectCSR(intent.Connector, intent.TargetID, intent.ReprotectJobID, csrDER)
		}
		if err != nil {
			log.Printf("trstctl-agent: job %d attempt %d: CA re-protection CSR: %v", job.JobID, job.Attempt, err)
			report(ctx, ch, job, OutcomeFailed, "retained host key could not create one durable CSR")
			return false
		}
	}
	if len(certPEM) == 0 {
		if tpmHeld {
			certPEM, chainPEM, fingerprint, err = signTPMReprotectCSR(ctx, ch, rollback, hostTPM, job, intent, csrDER, claim != nil)
		} else {
			certPEM, chainPEM, fingerprint, err = signHostCSR(ctx, signer, job, csrDER, claim != nil)
		}
		if err == nil {
			err = rollback.RecordReprotectCertificate(intent.Connector, intent.TargetID, intent.ReprotectJobID,
				certPEM, chainPEM, fingerprint)
		}
		if err != nil {
			if transport.IsCSRValidityRefusal(err) {
				report(ctx, ch, job, OutcomeFailed, transport.CSRValidityRefusalDetail)
			} else {
				report(ctx, ch, job, OutcomeFailed, "the control plane did not sign the retained-key CSR")
			}
			return false
		}
	}
	issued, err := certinfo.Inspect(certPEM)
	if err != nil || !sameHostRollbackFingerprint(issued.SHA256Fingerprint, fingerprint) ||
		!sameHostRollbackFingerprint(issued.SPKISHA256, intent.ReprotectPredecessorSPKISHA256) ||
		certinfo.VerifyHostname(certPEM, intent.VerifyServerName) != nil {
		report(ctx, ch, job, OutcomeFailed, "signed CA replacement differs from the retained subject key or reviewed listener")
		return false
	}
	if claim != nil {
		if err := claim.confirm(); err != nil {
			report(ctx, ch, job, OutcomeFailed, "CA re-protection claim was lost before installation")
			return false
		}
	}
	var key *secret.Buffer
	err = rollback.UseReprotectPredecessor(intent.Connector, intent.TargetID, intent.ReprotectJobID,
		intent.ReprotectPredecessorFingerprint, func(_, keyPEM []byte) error {
			var lockErr error
			key, lockErr = secret.NewFrom(keyPEM)
			return lockErr
		})
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "retained host key was unavailable for installation")
		return false
	}
	defer key.Destroy()
	if tpmHeld {
		// The TPM holds the private half: the key file's public key, read
		// through the TPM, is the certificate's.
		if err := tpmKeyFileMatches(hostTPM, key.Bytes(), issued.SPKISHA256); err != nil {
			report(ctx, ch, job, OutcomeFailed, "replacement certificate does not match the TPM-held host key")
			return false
		}
	} else if err := crypto.VerifyCertKeyMatchPEM(certPEM, key.Bytes()); err != nil {
		report(ctx, ch, job, OutcomeFailed, "replacement certificate does not match retained host key")
		return false
	}
	material := Material{"credential.cert_pem": certPEM, "credential.key_pem": key.Bytes()}
	if len(chainPEM) != 0 {
		material["credential.chain_pem"] = chainPEM
	}
	for ref, value := range management {
		material[ref] = value
	}
	installIntent := intent
	installIntent.Fingerprint = fingerprint
	if _, err := ExecuteOnHost(ctx, profile, installIntent, material, client); err != nil {
		log.Printf("trstctl-agent: job %d attempt %d: host install of the CA successor failed: %v", job.JobID, job.Attempt, err)
		restoreErr := rollbackReprotectHost(ctx, rollback, profile, client, intent, management)
		report(ctx, ch, job, OutcomeFailed, reprotectFailureDetail("CA successor could not be installed", restoreErr))
		return false
	}
	servingPEM, err := servingCertificatePEM(material)
	if err != nil || rollback.RecordDeploy(intent.Connector, intent.TargetID, fingerprint, servingPEM, key.Bytes()) != nil {
		restoreErr := rollbackReprotectHost(ctx, rollback, profile, client, intent, management)
		report(ctx, ch, job, OutcomeFailed, reprotectFailureDetail("CA successor installed but host rollback state could not be committed", restoreErr))
		return false
	}
	outcome, detail, evidence := postDeployVerificationWithNative(ctx, installIntent, material, profile.TLSProbeOpenSSL)
	if outcome != transport.OutcomeVerified {
		restoreErr := rollbackReprotectHost(ctx, rollback, profile, client, intent, management)
		report(ctx, ch, job, transport.OutcomeVerifyFailed, reprotectFailureDetail("CA successor not served: "+detail, restoreErr))
		return false
	}
	custody, err := HostRenewCustody(intent.Connector, intent.KeyCustody, "")
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "installed host key custody cannot be classified")
		return false
	}
	accepted, reportErr := reporter.ReportJobResultWithCustody(ctx, job.JobID, job.Attempt,
		outcome, detail, evidence, fingerprint, custody)
	logReportOutcome(job, outcome, accepted, reportErr)
	if accepted && reportErr == nil {
		if err := rollback.ClearReprotectPending(intent.Connector, intent.TargetID, intent.ReprotectJobID, fingerprint); err != nil {
			return false
		}
	}
	return accepted && reportErr == nil
}

func rollbackReprotectHost(ctx context.Context, store *HostRollbackStore, profile connector.LocalOpsConfig,
	client *http.Client, intent DeployIntent, management Material) error {
	return store.RestoreReprotect(intent.Connector, intent.TargetID, intent.ReprotectJobID,
		intent.ReprotectPredecessorFingerprint, func(oldCert, oldKey []byte) (bool, error) {
			oldInfo, err := certinfo.Inspect(oldCert)
			if err != nil {
				return false, err
			}
			material := Material{"credential.cert_pem": oldCert, "credential.key_pem": oldKey}
			for ref, value := range management {
				material[ref] = value
			}
			original := intent
			original.Fingerprint = oldInfo.SHA256Fingerprint
			if _, err := ExecuteOnHost(ctx, profile, original, material, client); err != nil {
				return false, err
			}
			outcome, _, _ := postDeployVerificationWithNative(ctx, original, material, profile.TLSProbeOpenSSL)
			if outcome != transport.OutcomeVerified {
				return false, errors.New("restored CA predecessor is not served")
			}
			return true, nil
		})
}

func reprotectFailureDetail(cause string, restoreErr error) string {
	if restoreErr != nil {
		return fmt.Sprintf("%s; predecessor restore failed: %v", cause, restoreErr)
	}
	return cause + "; exact predecessor restored and listener verified"
}

// createTPMRetainedHostKeyCSR has the TPM sign the re-protected CSR with the
// retained TSS2 key file's key (TPM-O1-L1), after checking that key is the
// predecessor's, by its SPKI.
func createTPMRetainedHostKeyCSR(h *hostKeyTPM, keyFile []byte, tmpl crypto.CertificateRequestTemplate, predecessorSPKISHA256 string) ([]byte, error) {
	publicDER, err := h.device.HostKeyPublicDER(keyFile)
	if err != nil {
		return nil, err
	}
	if !sameHostRollbackFingerprint(crypto.SHA256Hex(publicDER), predecessorSPKISHA256) {
		return nil, errors.New("relay: the retained TPM key file is not the predecessor's key")
	}
	return crypto.CreateHostSubjectCSR(tmpl, tpm.HostKeySigner(h.device, keyFile, publicDER))
}

// signTPMReprotectCSR has the TPM certify the retained key over this job's
// binding and sends the CSR with that attestation (TPM-O1-L1).
func signTPMReprotectCSR(ctx context.Context, ch Channel, rollback *HostRollbackStore, h *hostKeyTPM, job Job, intent DeployIntent,
	csrDER []byte, maintained bool) ([]byte, []byte, string, error) {
	attested, ok := ch.(AttestedCSRSigner)
	if !ok {
		return nil, nil, "", errors.New("relay: this channel cannot send a TPM key attestation")
	}
	var attestation []byte
	err := rollback.UseReprotectPredecessor(intent.Connector, intent.TargetID, intent.ReprotectJobID,
		intent.ReprotectPredecessorFingerprint, func(_, keyFile []byte) error {
			var attestErr error
			attestation, attestErr = h.attest(job.JobID, keyFile, csrDER)
			return attestErr
		})
	if err != nil {
		log.Printf("trstctl-agent: job %d attempt %d: host key TPM attestation: %v", job.JobID, job.Attempt, err)
		return nil, nil, "", err
	}
	return signHostCSRWithKeyAttestation(ctx, attested, job, csrDER, attestation, maintained)
}

// tpmKeyFileMatches reports whether the TSS2 key file's public key, read
// through the TPM, has the certificate's SPKI hash.
func tpmKeyFileMatches(h *hostKeyTPM, keyFile []byte, spkiSHA256 string) error {
	publicDER, err := h.device.HostKeyPublicDER(keyFile)
	if err != nil {
		return err
	}
	if !sameHostRollbackFingerprint(crypto.SHA256Hex(publicDER), spkiSHA256) {
		return errors.New("relay: the TPM key file's public key is not the certificate's")
	}
	return nil
}
