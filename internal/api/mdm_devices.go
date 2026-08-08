// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/mdm"
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
	a.writeJSON(w, http.StatusOK, mdmTraceResponse{
		Trace:    a.buildDeviceTrace(c),
		Guidance: mdmGuidance,
	})
}

// buildDeviceTrace turns what each system reported into the trace.
//
// The SCEP and CA steps are inferred from what this system itself did — a
// correlation row exists only because a transaction did, and an identity id
// exists only because we minted one. The install step is the MDM's claim and is
// labelled with which MDM said so, because an operator deciding whether to
// trust it needs to know the source.
func (a *API) buildDeviceTrace(c store.MDMDeviceCorrelation) mdm.DeviceTrace {
	var observed []mdm.Observation
	if c.TransactionID != "" {
		observed = append(observed, mdm.Observation{
			Stage: mdm.StageRequested, Outcome: mdm.OutcomeOK, At: c.UpdatedAt,
			Detail: "SCEP transaction " + c.TransactionID + " was accepted.", Source: "scep",
		})
	}
	if c.IdentityID != "" {
		observed = append(observed, mdm.Observation{
			Stage: mdm.StageIssued, Outcome: mdm.OutcomeOK, At: c.UpdatedAt,
			Detail: "Certificate minted.", Source: "ca",
		})
	}
	if c.ObservedAt != nil {
		detail := c.InstallDetail
		if detail == "" && c.InstallState == string(mdm.OutcomeUnknown) {
			detail = "The MDM did not report this device's profile state."
		}
		observed = append(observed, mdm.Observation{
			Stage: mdm.StageInstalled, Outcome: mdm.Outcome(c.InstallState),
			At: *c.ObservedAt, Detail: detail, Source: c.MDM,
		})
	}
	return mdm.BuildTrace(mdm.DeviceTrace{
		DeviceID: c.MDMDeviceID, MDMDeviceID: c.MDMDeviceID, MDM: c.MDM,
		DeviceName: c.DeviceName, SerialNumber: c.SerialNumber, TransactionID: c.TransactionID,
	}, observed)
}
