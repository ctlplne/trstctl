// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/discovery/netscan"
	"trstctl.com/trstctl/internal/discovery/segmentscan"
	"trstctl.com/trstctl/internal/discovery/sshscan"
	"trstctl.com/trstctl/internal/sshinv"
)

// Network and SSH sweeps from inside the segment (epic C2).
//
// Network scanning has always run from the control plane's worker, which means
// it could only ever see what the control plane could route to. For a hosted
// deployment that is the public internet and nothing else — so the scan
// inventoried the estate's least interesting surface and reported it as the
// estate. The segments that actually hold unmanaged certificates are the ones
// behind a firewall: a management VLAN, a DMZ, a lab nobody admits owning.
//
// A relay already sits in those segments. Moving the sweep there is the whole
// epic, and the scanners needed no changes to allow it — they were already
// dependency-light, and the one thing keeping them out of the agent binary was
// a store-backed sink whose only caller was a control-plane test.
//
// The reserved-range guards travel with the scanner. They are not a
// control-plane policy that a relay escapes: netscan refuses loopback,
// link-local and multicast targets unless explicitly permitted, and it does
// that in the scanner itself, so it does it here too.

// KindDiscoveryRun is the job kind for a segment sweep.
const KindDiscoveryRun = "discovery.run"

// DiscoveryScanIntent is the shared, bounded relay command.
type DiscoveryScanIntent = segmentscan.Intent

// Discovery sweep modes.
const (
	DiscoveryModeTLS = segmentscan.ModeTLS
	DiscoveryModeSSH = segmentscan.ModeSSH
)

// DiscoveryFinding is one certificate or host key the relay found, in the
// metadata-only shape every other agent finding uses.
type DiscoveryFinding = segmentscan.Finding

// DiscoveryReport is what a relay returns for one sweep.
type DiscoveryReport = segmentscan.Report

// relayScanSink collects findings in memory for one sweep. The relay holds no
// database — findings travel back over the channel the agent opened, and the
// control plane is the only thing that writes them (AN-2).
type relayScanSink struct{ findings []DiscoveryFinding }

func (s *relayScanSink) Record(_ context.Context, f netscan.Found) error {
	s.findings = append(s.findings, discoveryFindingFromCert(f.Address, f.Cert))
	return nil
}

type relaySSHSink struct{ findings []DiscoveryFinding }

func (s *relaySSHSink) Record(_ context.Context, f sshinv.Found) error {
	s.findings = append(s.findings, DiscoveryFinding{
		Address:     f.Location,
		Fingerprint: f.Fingerprint,
		KeyType:     f.KeyType,
	})
	return nil
}

func discoveryFindingFromCert(address string, info certinfo.Info) DiscoveryFinding {
	sans := append([]string(nil), info.DNSNames...)
	sans = append(sans, info.IPAddresses...)
	sans = append(sans, info.EmailAddresses...)
	sans = append(sans, info.URIs...)
	out := DiscoveryFinding{
		Address:       address,
		Fingerprint:   info.SHA256Fingerprint,
		Subject:       info.Subject,
		Issuer:        info.Issuer,
		Serial:        info.SerialNumber,
		KeyType:       info.KeyAlgorithm,
		SANs:          sans,
		PublicKeyBits: info.PublicKeyBits,
		IsCA:          info.IsCA,
	}
	if !info.NotBefore.IsZero() {
		out.NotBefore = info.NotBefore.UTC().Format("2006-01-02T15:04:05Z")
	}
	if !info.NotAfter.IsZero() {
		out.NotAfter = info.NotAfter.UTC().Format("2006-01-02T15:04:05Z")
	}
	return out
}

// Sweep runs one discovery sweep from this relay's vantage.
func Sweep(ctx context.Context, intent DiscoveryScanIntent) (DiscoveryReport, error) {
	targets := dedupeEndpoints(intent.Targets)
	if len(targets) == 0 {
		return DiscoveryReport{}, errors.New("relay: discovery sweep names no targets")
	}
	if intent.DryRun {
		return DiscoveryReport{Mode: intent.Mode, Findings: []DiscoveryFinding{}, Targets: len(targets)}, nil
	}
	switch intent.Mode {
	case DiscoveryModeTLS:
		sink := &relayScanSink{}
		var opts []netscan.Option
		opts = append(opts,
			netscan.WithAllowRFC1918Targets(intent.AllowRFC1918 || intent.AllowReservedRanges),
			netscan.WithAllowLoopbackTargets(intent.AllowLoopback || intent.AllowReservedRanges),
		)
		rep := netscan.New(sink, opts...).Scan(ctx, targets)
		return DiscoveryReport{
			Mode: DiscoveryModeTLS, Findings: sortFindings(sink.findings),
			Targets: rep.Targets, Discovered: rep.Discovered,
			Failed: rep.Failed, Rejected: rep.Rejected, Blocked: rep.Blocked,
		}, nil
	case DiscoveryModeSSH:
		sink := &relaySSHSink{}
		var opts []sshscan.Option
		opts = append(opts,
			sshscan.WithAllowRFC1918Targets(intent.AllowRFC1918 || intent.AllowReservedRanges),
			sshscan.WithAllowLoopbackTargets(intent.AllowLoopback || intent.AllowReservedRanges),
		)
		scanner := sshscan.New(sink, opts...)
		defer scanner.Close()
		rep := scanner.Scan(ctx, targets)
		return DiscoveryReport{
			Mode: DiscoveryModeSSH, Findings: sortFindings(sink.findings),
			Targets: rep.Targets, Discovered: rep.Discovered,
			Failed: rep.Failed, Rejected: rep.Rejected, Blocked: rep.Blocked,
		}, nil
	default:
		return DiscoveryReport{}, fmt.Errorf("relay: unknown discovery mode %q", intent.Mode)
	}
}

// sortFindings gives a sweep a stable order so two passes over an unchanged
// segment diff to nothing.
func sortFindings(in []DiscoveryFinding) []DiscoveryFinding {
	sort.Slice(in, func(i, j int) bool {
		if in[i].Address != in[j].Address {
			return in[i].Address < in[j].Address
		}
		return in[i].Fingerprint < in[j].Fingerprint
	})
	return in
}

// runDiscoverySweep executes a discovery.run job.
//
// Like the other probe kinds, a sweep that found nothing is a successful JOB. An
// empty segment is an answer, and reporting it as a failure would requeue the
// sweep forever against a range that is genuinely empty.
func runDiscoverySweep(ctx context.Context, ch Channel, job Job) bool {
	var intent DiscoveryScanIntent
	if err := json.Unmarshal(job.Payload, &intent); err != nil {
		report(ctx, ch, job, OutcomeFailed, "job payload is not a discovery sweep intent")
		return false
	}
	sweep, err := Sweep(ctx, intent)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "discovery sweep could not run")
		return false
	}
	detail, err := json.Marshal(sweep)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "discovery findings could not be encoded")
		return false
	}
	report(ctx, ch, job, OutcomeExecuted, string(detail))
	return true
}
