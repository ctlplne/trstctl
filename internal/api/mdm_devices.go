// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/mdm"
	"trstctl.com/trstctl/internal/mdmevidence"
	"trstctl.com/trstctl/internal/store"
)

// The served device-correlation view and per-device enrollment trace (I5).
//
// There is deliberately no write route. "Read-only proven (no MDM writes)" is
// held as an absence — no handler here constructs anything but a read, and
// internal/mdm has no request builder that can emit another verb — rather than
// as a flag somebody could flip. A bad write to an MDM does not corrupt a
// record; it pushes a profile to real laptops.

type mdmDeviceResponse struct {
	MDM          string `json:"mdm"`
	MDMDeviceID  string `json:"mdm_device_id"`
	DeviceName   string `json:"device_name,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	// TransactionID ties this to the SCEP exchange; without it a device with two
	// enrollments cannot be told apart from two devices.
	TransactionID string `json:"transaction_id,omitempty"`
	IdentityID    string `json:"identity_id,omitempty"`
	InstallState  string `json:"install_state"`
	InstallDetail string `json:"install_detail,omitempty"`
	// ObservedAt empty means NEVER observed, which is distinct from observed
	// long ago — an operator deciding whether to trust a stale answer needs to
	// tell those apart.
	ObservedAt string `json:"observed_at,omitempty"`
	// RenewalNotAfter / RenewalAtRisk / RenewalDetail are the offline-renewal
	// check (I5): a SCEP device renews by CHECKING IN, so a device the MDM has
	// not seen since its certificate's renewal window opened will silently
	// miss its renewal while every dashboard stays green.
	RenewalNotAfter string `json:"renewal_not_after,omitempty"`
	RenewalAtRisk   bool   `json:"renewal_at_risk,omitempty"`
	RenewalDetail   string `json:"renewal_detail,omitempty"`
}

type mdmDeviceList struct {
	Items []mdmDeviceResponse `json:"items"`
	// Unobserved is counted separately from failed. They are different problems:
	// one is a device that reported trouble, the other is a device nothing has
	// heard from, and a single "unhealthy" number would merge them.
	Failed     int `json:"failed"`
	Unobserved int `json:"unobserved"`
	// RenewalAtRisk counts devices whose certificate is inside (or past) its
	// renewal window while the MDM has not seen the device since the window
	// opened. Counted apart from failed: nothing failed yet, and that is the
	// problem.
	RenewalAtRisk int    `json:"renewal_at_risk"`
	Guidance      string `json:"guidance"`
}

const mdmGuidance = "This correlation is READ-ONLY: nothing here writes to Intune or Jamf, and no " +
	"configuration turns that on. An 'unknown' install state is NOT a failure — an MDM we could not " +
	"reach tells us nothing about the device, and treating it as failed would send somebody to " +
	"re-push a profile that is already installed. Devices with no matching certificate and " +
	"certificates with no matching device are both reported, because a correlation that showed only " +
	"its successes would make an estate look covered by hiding the gaps."

type mdmTraceResponse struct {
	Trace    mdm.DeviceTrace `json:"trace"`
	Guidance string          `json:"guidance"`
}

func toMDMDeviceResponse(c store.MDMDeviceCorrelation) mdmDeviceResponse {
	out := mdmDeviceResponse{
		MDM: c.MDM, MDMDeviceID: c.MDMDeviceID, DeviceName: c.DeviceName,
		SerialNumber: c.SerialNumber, TransactionID: c.TransactionID,
		IdentityID: c.IdentityID, InstallState: c.InstallState, InstallDetail: c.InstallDetail,
	}
	if c.ObservedAt != nil {
		out.ObservedAt = c.ObservedAt.UTC().Format(time.RFC3339)
	}
	return out
}

func (a *API) listMDMDevices(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	which := strings.TrimSpace(r.URL.Query().Get("mdm"))
	if which != "" && which != mdm.MDMIntune && which != mdm.MDMJamf {
		a.writeError(w, errStatus(http.StatusBadRequest, "mdm must be intune or jamf"))
		return
	}
	rows, err := a.store.ListMDMDeviceCorrelations(r.Context(), tenantID, which, 200)
	if err != nil {
		a.writeError(w, err)
		return
	}
	// The serial->identity join carries not_after for the renewal check, and
	// per-MDM window overrides come from the poll schedules. Both reads are
	// best-effort: a failed join must degrade to "no verdict", never to a
	// blank device list.
	bySerial, _ := a.store.IdentitiesBySerial(r.Context(), tenantID)
	windows := map[string]int{}
	if schedules, err := a.store.ListMDMPollSchedules(r.Context(), tenantID); err == nil {
		for _, sch := range schedules {
			windows[sch.MDM] = sch.RenewalWindowDays
		}
	}
	now := time.Now().UTC()
	out := mdmDeviceList{Items: []mdmDeviceResponse{}, Guidance: mdmGuidance}
	for _, row := range rows {
		switch row.InstallState {
		case string(mdm.OutcomeFailed):
			out.Failed++
		case string(mdm.OutcomeUnknown):
			out.Unobserved++
		}
		item := toMDMDeviceResponse(row)
		if join, ok := bySerial[strings.ToUpper(strings.TrimSpace(row.SerialNumber))]; ok && join.NotAfter != nil {
			item.RenewalNotAfter = join.NotAfter.UTC().Format(time.RFC3339)
			atRisk, detail := mdm.RenewalRisk(join.NotAfter, row.ObservedAt, windows[row.MDM], now)
			item.RenewalAtRisk, item.RenewalDetail = atRisk, detail
			if atRisk {
				out.RenewalAtRisk++
			}
		}
		out.Items = append(out.Items, item)
	}
	a.writeJSON(w, http.StatusOK, out)
}

// getMDMDeviceTrace answers "where did this device's enrollment break".
func (a *API) getMDMDeviceTrace(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	which := strings.TrimSpace(r.PathValue("mdm"))
	if which != mdm.MDMIntune && which != mdm.MDMJamf {
		a.writeError(w, errStatus(http.StatusBadRequest, "mdm must be intune or jamf"))
		return
	}
	c, err := a.store.GetMDMDeviceCorrelation(r.Context(), tenantID, which, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	trace, err := a.buildDeviceTrace(r.Context(), tenantID, c)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, mdmTraceResponse{
		Trace:    trace,
		Guidance: mdmGuidance,
	})
}

// buildDeviceTrace turns what each system reported into the trace.
//
// Correlation IDs are JOIN KEYS, not evidence. Requested, issued, and renewing
// consume the immutable, device-serial-bound SCEP attempt events written by the
// actual protocol handler. Installed consumes only an attributed MDM profile or
// certificate observation. Generic identity transitions never enter this trace:
// they do not prove that this device made this transaction (AUD-50/AUD-57).
func (a *API) buildDeviceTrace(ctx context.Context, tenantID string, c store.MDMDeviceCorrelation) (mdm.DeviceTrace, error) {
	var observed []mdm.Observation
	attempts, err := mdmevidence.Load(ctx, a.log, tenantID, c.SerialNumber, c.TransactionID)
	if err != nil {
		return mdm.DeviceTrace{}, err
	}
	selectedIndex := -1
	if c.TransactionID != "" {
		for i := range attempts {
			if attempts[i].TransactionID == c.TransactionID {
				selectedIndex = i
				break
			}
		}
	}
	if selectedIndex < 0 && len(attempts) > 0 {
		selectedIndex = len(attempts) - 1
	}
	transactionID := c.TransactionID
	if selectedIndex >= 0 {
		attempt := attempts[selectedIndex]
		transactionID = attempt.TransactionID
		if attempt.Request != nil {
			observed = append(observed, mdm.Observation{
				Stage: mdm.StageRequested, Outcome: evidenceOutcome(attempt.Request.Outcome),
				At: attempt.Request.At, Detail: attempt.Request.Detail, Source: "scep",
			})
		}
		if attempt.Issuance != nil {
			observed = append(observed, mdm.Observation{
				Stage: mdm.StageIssued, Outcome: evidenceOutcome(attempt.Issuance.Outcome),
				At: attempt.Issuance.At, Detail: attempt.Issuance.Detail, Source: "scep",
			})
		}
		appendRenewalObservation(ctx, a.store, tenantID, c, attempts, selectedIndex, &observed)
	}
	if c.InstallState != string(mdm.OutcomeUnknown) {
		detail := c.InstallDetail
		at := c.UpdatedAt
		if at.IsZero() && c.ObservedAt != nil {
			at = *c.ObservedAt
		}
		observed = append(observed, mdm.Observation{
			Stage: mdm.StageInstalled, Outcome: mdm.Outcome(c.InstallState),
			At: at, Detail: detail, Source: c.MDM,
		})
	}
	return mdm.BuildTrace(mdm.DeviceTrace{
		DeviceID: c.MDMDeviceID, MDMDeviceID: c.MDMDeviceID, MDM: c.MDM,
		DeviceName: c.DeviceName, SerialNumber: c.SerialNumber, TransactionID: transactionID,
	}, observed), nil
}

func evidenceOutcome(value string) mdm.Outcome {
	switch value {
	case string(mdm.OutcomeOK):
		return mdm.OutcomeOK
	case string(mdm.OutcomeFailed):
		return mdm.OutcomeFailed
	case string(mdm.OutcomePending):
		return mdm.OutcomePending
	default:
		return mdm.OutcomeUnknown
	}
}

func appendRenewalObservation(ctx context.Context, st *store.Store, tenantID string, c store.MDMDeviceCorrelation, attempts []mdmevidence.Attempt, selectedIndex int, observed *[]mdm.Observation) {
	firstIssued := -1
	lastIssued := -1
	for i := range attempts {
		if attempts[i].Issuance != nil && attempts[i].Issuance.Outcome == string(mdm.OutcomeOK) && attempts[i].CertificateSerial != "" {
			if firstIssued < 0 {
				firstIssued = i
			}
			lastIssued = i
		}
	}
	selected := attempts[selectedIndex]
	if firstIssued >= 0 && selectedIndex > firstIssued {
		outcome := mdm.OutcomePending
		at := selected.At()
		detail := "A later SCEP transaction was observed; its terminal renewal result has not been recorded yet."
		if selected.Issuance != nil {
			outcome = evidenceOutcome(selected.Issuance.Outcome)
			at = selected.Issuance.At
			if outcome == mdm.OutcomeOK {
				detail = "A later SCEP transaction minted certificate " + selected.CertificateSerial + "; MDM readback decides whether it installed."
			} else {
				detail = selected.Issuance.Detail
			}
		}
		*observed = append(*observed, mdm.Observation{Stage: mdm.StageRenewing, Outcome: outcome, At: at, Detail: detail, Source: "scep"})
		return
	}
	if lastIssued < 0 || attempts[lastIssued].CertificateNotAfter.IsZero() {
		return
	}
	windowDays := 0
	if st != nil {
		if schedules, err := st.ListMDMPollSchedules(ctx, tenantID); err == nil {
			for _, schedule := range schedules {
				if schedule.MDM == c.MDM {
					windowDays = schedule.RenewalWindowDays
					break
				}
			}
		}
	}
	notAfter := attempts[lastIssued].CertificateNotAfter
	atRisk, detail := mdm.RenewalRisk(&notAfter, c.ObservedAt, windowDays, time.Now().UTC())
	if atRisk {
		*observed = append(*observed, mdm.Observation{
			Stage: mdm.StageRenewing, Outcome: mdm.OutcomeUnknown, At: attempts[lastIssued].CertificateNotAfter,
			Detail: detail + " No later SCEP renewal transaction is present; bring the device online and trigger an MDM check-in.", Source: c.MDM,
		})
	}
}
