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

// DiscoveryScanIntent is the job payload: what to sweep, and how.
type DiscoveryScanIntent struct {
	// Mode selects the sweep. "tls" probes for served certificates; "ssh"
	// collects host keys. They are separate because they answer different
	// questions and an operator schedules them differently.
	Mode string `json:"mode"`
	// Targets are hosts, host:port pairs, or CIDR ranges. The scanner expands
	// and bounds them; a relay never invents targets of its own.
	Targets []string `json:"targets"`
	// AllowReservedRanges permits loopback and other reserved addresses. It
	// exists for lab and test use and is off by default: a sweep that quietly
	// probed 127.0.0.1 on every host in a fleet would be a surprising thing for
	// a certificate manager to do.
	AllowReservedRanges bool `json:"allow_reserved_ranges,omitempty"`
}

// Discovery sweep modes.
const (
	DiscoveryModeTLS = "tls"
	DiscoveryModeSSH = "ssh"
)

// DiscoveryFinding is one certificate or host key the relay found, in the
// metadata-only shape every other agent finding uses.
type DiscoveryFinding struct {
	// Address is where it was served, which is the fact a control-plane scan
	// could not have learned for an unroutable segment.
	Address string `json:"address"`
	// Fingerprint identifies the credential. For TLS it is the certificate's
	// SHA-256; for SSH it is the host key's.
	Fingerprint string `json:"fingerprint"`
	Subject     string `json:"subject,omitempty"`
	Issuer      string `json:"issuer,omitempty"`
	Serial      string `json:"serial,omitempty"`
	KeyType     string `json:"key_type,omitempty"`
	NotBefore   string `json:"not_before,omitempty"`
	NotAfter    string `json:"not_after,omitempty"`
}

// DiscoveryReport is what a relay returns for one sweep.
type DiscoveryReport struct {
	Mode     string             `json:"mode"`
	Findings []DiscoveryFinding `json:"findings"`
	// The sweep's own counts. A sweep that reached nothing and a segment with
	// nothing in it must not read the same, which is why these are reported
	// rather than inferred from an empty findings list. Blocked in particular
	// is worth surfacing: it counts targets the reserved-range guard refused
	// before dialling, and an operator who scanned 127.0.0.0/8 by accident
	// should see that as a refusal rather than as an empty segment.
	Targets    int `json:"targets"`
	Discovered int `json:"discovered"`
	Failed     int `json:"failed"`
	Rejected   int `json:"rejected"`
	Blocked    int `json:"blocked"`
}

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
	out := DiscoveryFinding{
		Address:     address,
		Fingerprint: info.SHA256Fingerprint,
		Subject:     info.Subject,
		Issuer:      info.Issuer,
		Serial:      info.SerialNumber,
		KeyType:     info.KeyAlgorithm,
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
	switch intent.Mode {
	case DiscoveryModeTLS:
		sink := &relayScanSink{}
		var opts []netscan.Option
		if intent.AllowReservedRanges {
			opts = append(opts, netscan.WithAllowLoopbackTargets(true))
		}
		rep := netscan.New(sink, opts...).Scan(ctx, targets)
		return DiscoveryReport{
			Mode: DiscoveryModeTLS, Findings: sortFindings(sink.findings),
			Targets: rep.Targets, Discovered: rep.Discovered,
			Failed: rep.Failed, Rejected: rep.Rejected, Blocked: rep.Blocked,
		}, nil
	case DiscoveryModeSSH:
		sink := &relaySSHSink{}
		var opts []sshscan.Option
		if intent.AllowReservedRanges {
			opts = append(opts, sshscan.WithAllowLoopbackTargets(true))
		}
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
