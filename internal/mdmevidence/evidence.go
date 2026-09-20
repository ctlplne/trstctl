// SPDX-License-Identifier: BUSL-1.1

// Package mdmevidence reads immutable SCEP attempt facts for the MDM
// correlation and trace surfaces. It deliberately lives outside internal/mdm:
// the latter is linked into the relay binary and must remain an agent-safe leaf
// with no event-log dependency.
package mdmevidence

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/protocols/scep"
)

// Fact is one request or terminal issuance observation with its event time.
type Fact struct {
	Outcome string
	Detail  string
	At      time.Time
}

// Attempt is one transaction reconstructed only from immutable protocol facts.
// A missing Request or Issuance fact stays missing; the transaction id and
// device serial are join keys and never manufacture an outcome.
type Attempt struct {
	TransactionID          string
	DeviceSerial           string
	Profile                string
	Request                *Fact
	Issuance               *Fact
	CertificateSerial      string
	CertificateFingerprint string
	CertificateNotAfter    time.Time
}

// At is the earliest durable evidence time for the attempt.
func (a Attempt) At() time.Time {
	if a.Request != nil {
		return a.Request.At
	}
	if a.Issuance != nil {
		return a.Issuance.At
	}
	return time.Time{}
}

// Load returns the tenant's attempts matching the exact normalized device
// serial. transactionID optionally admits one legacy terminal event whose old
// payload had no serial; this preserves honest request history for rows written
// before AUD-50 without inventing issued certificate evidence.
func Load(ctx context.Context, log *events.Log, tenantID, deviceSerial, transactionID string) ([]Attempt, error) {
	if log == nil || strings.TrimSpace(tenantID) == "" {
		return nil, nil
	}
	wantSerial := normalizeSerial(deviceSerial)
	wantTransaction := strings.TrimSpace(transactionID)
	byTransaction := map[string]*Attempt{}
	err := log.Replay(ctx, 0, func(ev events.Event) error {
		if ev.TenantID != tenantID {
			return nil
		}
		switch ev.Type {
		case scep.EventRequestObserved, scep.EventIssuanceObserved:
			var payload scep.AttemptEvidence
			if err := json.Unmarshal(ev.Data, &payload); err != nil {
				return nil
			}
			payload.TransactionID = strings.TrimSpace(payload.TransactionID)
			payload.DeviceSerial = normalizeSerial(payload.DeviceSerial)
			if payload.TransactionID == "" || payload.DeviceSerial == "" {
				return nil
			}
			if wantSerial != "" && payload.DeviceSerial != wantSerial {
				return nil
			}
			if wantSerial == "" && wantTransaction != "" && payload.TransactionID != wantTransaction {
				return nil
			}
			attempt := byTransaction[payload.TransactionID]
			if attempt == nil {
				attempt = &Attempt{TransactionID: payload.TransactionID, DeviceSerial: payload.DeviceSerial, Profile: payload.Profile}
				byTransaction[payload.TransactionID] = attempt
			}
			fact := &Fact{Outcome: payload.Outcome, Detail: payload.Detail, At: ev.Time.UTC()}
			if ev.Type == scep.EventRequestObserved {
				attempt.Request = newerFact(attempt.Request, fact)
				return nil
			}
			attempt.Issuance = newerFact(attempt.Issuance, fact)
			if payload.Outcome == "ok" {
				attempt.CertificateSerial = payload.CertificateSerial
				attempt.CertificateFingerprint = payload.CertificateFingerprint
				attempt.CertificateNotAfter = payload.CertificateNotAfter.UTC()
			}
		case "protocol.scep.enroll":
			// Compatibility for pre-AUD-50 rows: the old event proves that the
			// exact transaction reached a terminal SCEP decision, but it carries
			// no device serial or minted certificate identity. Only an existing
			// correlation row may select it by transaction id, and it can prove
			// requested/accepted — never issued or renewing.
			if wantTransaction == "" {
				return nil
			}
			var legacy struct {
				Decision      string `json:"decision"`
				Reason        string `json:"reason"`
				TransactionID string `json:"transaction_id"`
				Profile       string `json:"profile"`
			}
			if err := json.Unmarshal(ev.Data, &legacy); err != nil || strings.TrimSpace(legacy.TransactionID) != wantTransaction {
				return nil
			}
			if byTransaction[wantTransaction] != nil {
				return nil
			}
			outcome := "failed"
			if legacy.Decision == "allow" {
				outcome = "ok"
			}
			detail := strings.TrimSpace(legacy.Reason)
			if detail == "" {
				detail = "Legacy SCEP terminal evidence was recorded before certificate identity fields were available."
			}
			byTransaction[wantTransaction] = &Attempt{
				TransactionID: wantTransaction, DeviceSerial: wantSerial, Profile: legacy.Profile,
				Request: &Fact{Outcome: outcome, Detail: detail, At: ev.Time.UTC()},
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]Attempt, 0, len(byTransaction))
	for _, attempt := range byTransaction {
		out = append(out, *attempt)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].At().Equal(out[j].At()) {
			return out[i].TransactionID < out[j].TransactionID
		}
		return out[i].At().Before(out[j].At())
	})
	return out, nil
}

// Latest returns the most recent immutable attempt for an exact device serial.
func Latest(ctx context.Context, log *events.Log, tenantID, deviceSerial string) (Attempt, bool, error) {
	attempts, err := Load(ctx, log, tenantID, deviceSerial, "")
	if err != nil || len(attempts) == 0 {
		return Attempt{}, false, err
	}
	return attempts[len(attempts)-1], true, nil
}

func newerFact(current, next *Fact) *Fact {
	if current == nil || !next.At.Before(current.At) {
		return next
	}
	return current
}

func normalizeSerial(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}
