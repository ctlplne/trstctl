// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"reflect"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/succession"
	"trstctl.com/trstctl/internal/succession/recovery"
)

// PCAS recovery ceremony inputs are public except for PrivateKey. Every mode
// runs as a one-shot signer process: no control-plane HTTP/SQL dependency and no
// custodian key passes through the browser or the serving signer process.
type pcasOfflineOptions struct {
	Mode                string
	ID                  string
	PrivateKey          string
	PrivateOut          string
	PublicOut           string
	PolicyFile          string
	ChainFile           string
	SuccessorFile       string
	PinnedRootFile      string
	StatementFile       string
	RosterSignatureFile string
	ApprovalsFile       string
	Nonce               string
	Output              string
}

type pcasOfflinePolicy struct {
	IdentityID   string              `json:"identity_id"`
	Threshold    int                 `json:"threshold"`
	Roster       []recovery.Approver `json:"roster"`
	TrustRootDER []byte              `json:"trust_root_der"`
	UpdatedAt    string              `json:"updated_at,omitempty"`
}

type pcasRosterSignature struct {
	Threshold int                 `json:"Threshold"`
	Roster    []recovery.Approver `json:"Roster"`
	RosterSig []byte              `json:"RosterSig"`
}

// The locked key exposes digest signing so raw private material stays in the
// protected buffer. Recovery's message-signing interface is adapted here with
// the crypto boundary's SHA-256 helper, which VerifyMessage also uses.
type pcasOfflineSigner struct{ *crypto.LockedSigner }

func (s pcasOfflineSigner) Sign(message []byte, opts crypto.SignOptions) ([]byte, error) {
	if opts.Hash != "" && opts.Hash != crypto.SHA256 {
		return nil, errors.New("PCAS offline ceremony requires SHA-256")
	}
	return crypto.SignMessage(s.LockedSigner, message)
}

func runOfflinePCASRecovery(o pcasOfflineOptions) error {
	switch o.Mode {
	case "keygen":
		return pcasOfflineKeygen(o)
	case "statement":
		return pcasOfflineStatement(o)
	case "roster":
		return pcasOfflineRoster(o)
	case "approve":
		return pcasOfflineApprove(o)
	case "assemble":
		return pcasOfflineAssemble(o)
	default:
		return errors.New("PCAS recovery mode must be keygen, statement, roster, approve, or assemble")
	}
}

func pcasOfflineKeygen(o pcasOfflineOptions) error {
	if o.ID == "" || o.PrivateOut == "" || o.PublicOut == "" || o.PrivateOut == o.PublicOut {
		return errors.New("PCAS keygen requires a distinct ID, private output and public output")
	}
	der, err := crypto.GeneratePKCS8(crypto.ECDSAP384)
	if err != nil {
		return err
	}
	defer secret.Wipe(der)
	key, err := crypto.NewLockedSignerFromPKCS8(crypto.ECDSAP384, der)
	if err != nil {
		return err
	}
	defer key.Destroy()
	entry, err := json.MarshalIndent(recovery.Approver{ID: o.ID, PubDER: key.Public().DER}, "", "  ")
	if err != nil {
		return err
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if privatePEM == nil {
		return errors.New("PCAS keygen could not encode private key")
	}
	defer secret.Wipe(privatePEM)
	if err := writeOfflineOutput(o.PrivateOut, privatePEM); err != nil {
		return err
	}
	if err := writeOfflineOutput(o.PublicOut, entry); err != nil {
		_ = os.Remove(o.PrivateOut) // only the file just created by this one-shot mode
		return err
	}
	return nil
}

func pcasOfflineStatement(o pcasOfflineOptions) error {
	if o.ChainFile == "" || o.SuccessorFile == "" || o.PinnedRootFile == "" || o.Output == "" {
		return errors.New("PCAS statement requires chain, prepared successor, independently pinned genesis root and output")
	}
	statement, err := buildPCASOfflineStatement(o)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(statement, "", "  ")
	if err != nil {
		return err
	}
	return writeOfflineOutput(o.Output, encoded)
}

func buildPCASOfflineStatement(o pcasOfflineOptions) (recovery.RecoveryStatement, error) {
	if o.ChainFile == "" || o.SuccessorFile == "" || o.PinnedRootFile == "" {
		return recovery.RecoveryStatement{}, errors.New("PCAS statement requires chain, prepared successor and independently pinned genesis root")
	}
	var pinned recovery.Approver
	if err := readOfflineJSON(o.PinnedRootFile, &pinned); err != nil {
		return recovery.RecoveryStatement{}, err
	}
	var chain struct {
		IdentityID         string                    `json:"identity_id"`
		Genesis            *succession.GenesisRecord `json:"genesis"`
		TrustRootPublicDER []byte                    `json:"trust_root_public_der"`
		Records            [][]byte                  `json:"records"`
		Count              int                       `json:"count"`
	}
	if err := readOfflineJSON(o.ChainFile, &chain); err != nil {
		return recovery.RecoveryStatement{}, err
	}
	if chain.Genesis == nil || chain.Count != len(chain.Records) || chain.Genesis.Epoch != 0 ||
		chain.IdentityID == "" || chain.Genesis.IdentityID != chain.IdentityID ||
		len(pinned.PubDER) == 0 || !bytes.Equal(pinned.PubDER, chain.TrustRootPublicDER) {
		return recovery.RecoveryStatement{}, errors.New("PCAS chain does not match the independently pinned genesis root and identity")
	}
	if err := succession.VerifyGenesis(pinned.PubDER, *chain.Genesis); err != nil {
		return recovery.RecoveryStatement{}, fmt.Errorf("PCAS genesis verification: %w", err)
	}
	// #nosec G115 -- Count equals len(Records) above: nonnegative and bounded by the 4 MiB input (CWE-190).
	nextEpoch := uint64(chain.Count) + 1
	var prepared struct {
		IdentityID      string `json:"identity_id"`
		DeploymentScope string `json:"deployment_scope"`
		Epoch           uint64 `json:"epoch"`
		Algorithm       string `json:"algorithm"`
		Handle          string `json:"handle"`
		PublicKeyDER    []byte `json:"public_key_der"`
		RequestID       string `json:"request_id"`
		SignerSignature []byte `json:"signer_signature"`
		EventID         string `json:"event_id"`
	}
	if err := readOfflineJSON(o.SuccessorFile, &prepared); err != nil {
		return recovery.RecoveryStatement{}, err
	}
	if prepared.IdentityID != chain.IdentityID || prepared.DeploymentScope != chain.Genesis.DeploymentScope ||
		prepared.Epoch != nextEpoch || prepared.Algorithm == "" || len(prepared.PublicKeyDER) == 0 ||
		prepared.Handle == "" || len(prepared.SignerSignature) == 0 || prepared.EventID == "" {
		return recovery.RecoveryStatement{}, errors.New("PCAS prepared successor does not bind the next epoch of this chain")
	}
	if chain.Count > 0 {
		var last struct{ Fields succession.CommitmentFields }
		if err := json.Unmarshal(chain.Records[chain.Count-1], &last); err != nil ||
			last.Fields.Epoch != uint64(chain.Count) || last.Fields.IdentityID != chain.IdentityID ||
			last.Fields.TenantID != chain.Genesis.TenantID || last.Fields.DeploymentScope != chain.Genesis.DeploymentScope {
			return recovery.RecoveryStatement{}, errors.New("PCAS chain head is malformed or does not bind this tenant and identity")
		}
	}
	nonce := o.Nonce
	if nonce == "" {
		random, err := crypto.RandomBytes(16)
		if err != nil {
			return recovery.RecoveryStatement{}, err
		}
		nonce = hex.EncodeToString(random)
		secret.Wipe(random)
	}
	if len(nonce) < 16 {
		return recovery.RecoveryStatement{}, errors.New("PCAS recovery nonce must contain at least 16 characters")
	}
	statement := recovery.RecoveryStatement{DeploymentScope: prepared.DeploymentScope,
		IdentityID: prepared.IdentityID, TenantID: chain.Genesis.TenantID, Epoch: prepared.Epoch,
		SuccessorAlg: prepared.Algorithm, SuccessorPub: prepared.PublicKeyDER, Nonce: nonce}
	return statement, nil
}

func readPCASPolicy(path string) (pcasOfflinePolicy, error) {
	var policy pcasOfflinePolicy
	if path == "" {
		return policy, errors.New("PCAS recovery policy file is required")
	}
	if err := readOfflineJSON(path, &policy); err != nil {
		return policy, err
	}
	if policy.IdentityID == "" || policy.Threshold < 1 || policy.Threshold > len(policy.Roster) || len(policy.TrustRootDER) == 0 {
		return policy, errors.New("PCAS recovery policy has no identity, valid quorum or trust root")
	}
	seenID, seenKey := map[string]bool{}, map[string]bool{}
	for _, member := range policy.Roster {
		if member.ID == "" || len(member.PubDER) == 0 || seenID[member.ID] || seenKey[string(member.PubDER)] {
			return policy, errors.New("PCAS recovery roster has an empty or repeated custodian")
		}
		seenID[member.ID], seenKey[string(member.PubDER)] = true, true
	}
	return policy, nil
}

func pcasOfflineRoster(o pcasOfflineOptions) error {
	if o.PrivateKey == "" || o.Output == "" {
		return errors.New("PCAS roster signing requires root private key and output")
	}
	policy, err := readPCASPolicy(o.PolicyFile)
	if err != nil {
		return err
	}
	root, err := loadPCASOfflineKey(o.PrivateKey)
	if err != nil {
		return err
	}
	defer root.Destroy()
	if !bytes.Equal(root.Public().DER, policy.TrustRootDER) {
		return errors.New("PCAS roster signer does not match the enforced recovery root")
	}
	sig, err := recovery.SignRoster(pcasOfflineSigner{root}, policy.Threshold, policy.Roster)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(pcasRosterSignature{Threshold: policy.Threshold, Roster: policy.Roster, RosterSig: sig}, "", "  ")
	if err != nil {
		return err
	}
	return writeOfflineOutput(o.Output, encoded)
}

func pcasOfflineApprove(o pcasOfflineOptions) error {
	if o.StatementFile == "" || o.PrivateKey == "" || o.ID == "" || o.Output == "" {
		return errors.New("PCAS approval requires statement, custodian ID, own private key and output")
	}
	policy, err := readPCASPolicy(o.PolicyFile)
	if err != nil {
		return err
	}
	var statement recovery.RecoveryStatement
	if err := readOfflineJSON(o.StatementFile, &statement); err != nil {
		return err
	}
	if statement.IdentityID != policy.IdentityID || statement.TenantID == "" || statement.DeploymentScope == "" ||
		statement.Epoch == 0 || statement.SuccessorAlg == "" || len(statement.SuccessorPub) == 0 || len(statement.Nonce) < 16 {
		return errors.New("PCAS recovery statement does not bind the policy identity and exact successor")
	}
	o.Nonce = statement.Nonce
	expected, err := buildPCASOfflineStatement(o)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(statement, expected) {
		return errors.New("PCAS recovery statement differs from the custodian's independently checked chain and successor")
	}
	key, err := loadPCASOfflineKey(o.PrivateKey)
	if err != nil {
		return err
	}
	defer key.Destroy()
	match := false
	for _, member := range policy.Roster {
		if member.ID == o.ID && bytes.Equal(member.PubDER, key.Public().DER) {
			match = true
		}
	}
	if !match {
		return errors.New("PCAS custodian key and ID do not match the enforced recovery roster")
	}
	sig, err := recovery.SignApproval(pcasOfflineSigner{key}, statement)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(recovery.Approval{ApproverID: o.ID, Signature: sig}, "", "  ")
	if err != nil {
		return err
	}
	return writeOfflineOutput(o.Output, encoded)
}

func pcasOfflineAssemble(o pcasOfflineOptions) error {
	if o.StatementFile == "" || o.RosterSignatureFile == "" || o.ApprovalsFile == "" || o.Output == "" {
		return errors.New("PCAS authorization assembly requires statement, roster signature, approval list and output")
	}
	policy, err := readPCASPolicy(o.PolicyFile)
	if err != nil {
		return err
	}
	var statement recovery.RecoveryStatement
	if err := readOfflineJSON(o.StatementFile, &statement); err != nil {
		return err
	}
	var roster pcasRosterSignature
	if err := readOfflineJSON(o.RosterSignatureFile, &roster); err != nil {
		return err
	}
	if roster.Threshold != policy.Threshold || len(roster.Roster) != len(policy.Roster) || len(roster.RosterSig) == 0 {
		return errors.New("PCAS signed roster differs from enforced recovery policy")
	}
	for i := range roster.Roster {
		if roster.Roster[i].ID != policy.Roster[i].ID || !bytes.Equal(roster.Roster[i].PubDER, policy.Roster[i].PubDER) {
			return errors.New("PCAS signed roster differs from enforced recovery policy")
		}
	}
	var approvals []recovery.Approval
	if err := readOfflineJSON(o.ApprovalsFile, &approvals); err != nil {
		return err
	}
	auth := recovery.RecoveryAuthorization{Statement: statement, Threshold: roster.Threshold,
		Roster: roster.Roster, RosterSig: roster.RosterSig, Approvals: approvals}
	if statement.IdentityID != policy.IdentityID {
		return errors.New("PCAS statement identity differs from enforced recovery policy")
	}
	if err := recovery.VerifyAuthorization(auth, policy.TrustRootDER, recovery.Expected{IdentityID: statement.IdentityID,
		TenantID: statement.TenantID, Epoch: statement.Epoch, SuccessorAlg: statement.SuccessorAlg,
		SuccessorPub: statement.SuccessorPub}); err != nil {
		return fmt.Errorf("PCAS recovery authorization: %w", err)
	}
	encoded, err := json.MarshalIndent(auth, "", "  ")
	if err != nil {
		return err
	}
	return writeOfflineOutput(o.Output, encoded)
}

func loadPCASOfflineKey(path string) (*crypto.LockedSigner, error) {
	raw, err := readPrivateFile(path)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(raw)
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("PCAS custodian key must be one unencrypted PKCS#8 PEM block")
	}
	defer secret.Wipe(block.Bytes)
	info, err := crypto.InspectPrivateKey(block.Bytes)
	if err != nil || info.Encrypted || info.Format != "PKCS8-DER" {
		return nil, errors.New("PCAS custodian key must be an unencrypted supported PKCS#8 key")
	}
	return crypto.NewLockedSignerFromPKCS8(info.Algorithm, block.Bytes)
}
