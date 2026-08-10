// SPDX-License-Identifier: MPL-2.0

package mdm

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"trstctl.com/trstctl/internal/secrettext"
)

const (
	intuneReportArchiveLimit = 16 << 20
	intuneReportCSVLimit     = 32 << 20
	intuneReportPollLimit    = 20
)

// ReadIntuneCertificateEvidence reads Microsoft's certificate-specific report.
// Creating an export job is the one POST in the MDM integration: it creates a
// report artifact, not an MDM policy, profile, assignment, or device mutation.
// Every resource path is fixed here; callers supply only profile IDs used for
// an exact local row filter.
func ReadIntuneCertificateEvidence(
	ctx context.Context,
	client *http.Client,
	base string,
	token []byte,
	profileIDs []string,
) ([]CertificateObservation, error) {
	profiles := exactProfileSet(profileIDs)
	if len(profiles) == 0 {
		return nil, nil
	}
	if client == nil {
		return nil, fmt.Errorf("mdm: Intune certificate report requires an HTTP client")
	}

	createURL, err := intuneExportJobsURL(base)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(struct {
		ReportName string   `json:"reportName"`
		Format     string   `json:"format"`
		Select     []string `json:"select"`
	}{
		ReportName: "CertificatesByRAPolicy",
		Format:     "csv",
		Select:     []string{"DeviceId", "PolicyId", "SerialNumber", "CertificateStatus", "ValidTo"},
	})
	if err != nil {
		return nil, fmt.Errorf("mdm: encode Intune certificate report request: %w", err)
	}
	job, err := readIntuneExportJob(ctx, client, http.MethodPost, createURL, token, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(job.ID) == "" {
		return nil, fmt.Errorf("mdm: Intune certificate report creation returned no job id")
	}
	if err := validateExportJobID(job.ID); err != nil {
		return nil, err
	}

	for attempt := 0; !intuneExportComplete(job.Status); attempt++ {
		if intuneExportFailed(job.Status) {
			return nil, fmt.Errorf("mdm: Intune certificate report job %q ended with status %q", job.ID, job.Status)
		}
		if attempt >= intuneReportPollLimit {
			return nil, fmt.Errorf("mdm: Intune certificate report job %q did not complete after %d bounded polls", job.ID, intuneReportPollLimit)
		}
		if attempt > 0 {
			timer := time.NewTimer(250 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
		pollURL, err := intuneExportJobURL(base, job.ID)
		if err != nil {
			return nil, err
		}
		job, err = readIntuneExportJob(ctx, client, http.MethodGet, pollURL, token, nil)
		if err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(job.URL) == "" {
		return nil, fmt.Errorf("mdm: completed Intune certificate report job %q returned no download URL", job.ID)
	}

	archive, err := downloadIntuneReport(ctx, client, job.URL)
	if err != nil {
		return nil, err
	}
	return parseIntuneCertificateArchive(archive, profiles)
}

type intuneExportJob struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	URL    string `json:"url"`
}

func readIntuneExportJob(
	ctx context.Context,
	client *http.Client,
	method, endpoint string,
	token []byte,
	body io.Reader,
) (intuneExportJob, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return intuneExportJob{}, fmt.Errorf("mdm: build Intune certificate report request: %w", err)
	}
	request.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
	request.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return intuneExportJob{}, fmt.Errorf("mdm: execute Intune certificate report request: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < http.StatusOK || response.StatusCode > 299 {
		detail, _ := readBounded(response.Body, 4096)
		return intuneExportJob{}, fmt.Errorf("mdm: Intune certificate report request failed with status %d: %s", response.StatusCode, strings.TrimSpace(string(detail)))
	}
	payload, err := readBounded(response.Body, responseLimit)
	if err != nil {
		return intuneExportJob{}, fmt.Errorf("mdm: read Intune certificate report job: %w", err)
	}
	var job intuneExportJob
	if err := json.Unmarshal(payload, &job); err != nil {
		return intuneExportJob{}, fmt.Errorf("mdm: decode Intune certificate report job: %w", err)
	}
	return job, nil
}

func intuneExportJobsURL(base string) (string, error) {
	u, err := parseAbsolute(base)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/beta/deviceManagement/reports/exportJobs"
	u.RawQuery, u.Fragment = "", ""
	return u.String(), nil
}

func intuneExportJobURL(base, id string) (string, error) {
	if err := validateExportJobID(id); err != nil {
		return "", err
	}
	u, err := parseAbsolute(base)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/beta/deviceManagement/reports/exportJobs('" + id + "')"
	u.RawQuery, u.Fragment = "", ""
	return u.String(), nil
}

func validateExportJobID(id string) error {
	if strings.TrimSpace(id) != id || id == "" || len(id) > 128 {
		return fmt.Errorf("mdm: Intune certificate report returned an invalid job id")
	}
	for _, r := range id {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("-._", r) {
			continue
		}
		return fmt.Errorf("mdm: Intune certificate report returned an unsafe job id")
	}
	return nil
}

func intuneExportComplete(status string) bool {
	return strings.EqualFold(strings.TrimSpace(status), "completed")
}

func intuneExportFailed(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "failed", "failure", "cancelled", "canceled", "error":
		return true
	default:
		return false
	}
}

func downloadIntuneReport(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("mdm: Intune certificate report returned an invalid download URL")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("mdm: build Intune certificate report download: %w", err)
	}
	// The signed download URL is a different authority. Never copy the Graph
	// bearer token onto it; possession of the signed URL is the authorization.
	request.Header.Set("Accept", "application/zip")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("mdm: download Intune certificate report: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < http.StatusOK || response.StatusCode > 299 {
		return nil, fmt.Errorf("mdm: Intune certificate report download failed with status %d", response.StatusCode)
	}
	archive, err := readBounded(response.Body, intuneReportArchiveLimit)
	if err != nil {
		return nil, fmt.Errorf("mdm: read Intune certificate report archive: %w", err)
	}
	return archive, nil
}

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > limit {
		return nil, fmt.Errorf("response exceeds %d-byte limit", limit)
	}
	return payload, nil
}

func parseIntuneCertificateArchive(archive []byte, profiles map[string]struct{}) ([]CertificateObservation, error) {
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, fmt.Errorf("mdm: open Intune certificate report archive: %w", err)
	}
	var observations []CertificateObservation
	var unpacked int64
	seenCSV := false
	for _, file := range zr.File {
		if !strings.HasSuffix(strings.ToLower(file.Name), ".csv") {
			continue
		}
		seenCSV = true
		remaining := intuneReportCSVLimit - unpacked
		if remaining < 0 || file.UncompressedSize64 > uint64(remaining) {
			return nil, fmt.Errorf("mdm: Intune certificate report expands beyond %d-byte limit", intuneReportCSVLimit)
		}
		rc, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("mdm: open Intune certificate report CSV: %w", err)
		}
		payload, readErr := readBounded(rc, remaining)
		closeErr := rc.Close()
		if readErr != nil {
			return nil, fmt.Errorf("mdm: read Intune certificate report CSV: %w", readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("mdm: close Intune certificate report CSV: %w", closeErr)
		}
		unpacked += int64(len(payload))
		rows, err := parseIntuneCertificateCSV(payload, profiles)
		if err != nil {
			return nil, err
		}
		observations = append(observations, rows...)
	}
	if !seenCSV {
		return nil, fmt.Errorf("mdm: Intune certificate report archive contained no CSV")
	}
	return observations, nil
}

func parseIntuneCertificateCSV(payload []byte, profiles map[string]struct{}) ([]CertificateObservation, error) {
	reader := csv.NewReader(bytes.NewReader(payload))
	reader.ReuseRecord = false
	rows, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("mdm: parse Intune certificate report CSV: %w", err)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("mdm: Intune certificate report CSV has no header")
	}
	columns := make(map[string]int, len(rows[0]))
	for index, name := range rows[0] {
		name = strings.TrimPrefix(strings.TrimSpace(name), "\ufeff")
		columns[strings.ToLower(name)] = index
	}
	required := []string{"deviceid", "policyid", "serialnumber", "certificatestatus", "validto"}
	for _, name := range required {
		if _, ok := columns[name]; !ok {
			return nil, fmt.Errorf("mdm: Intune certificate report CSV is missing required column %q", name)
		}
	}
	value := func(row []string, name string) string {
		index := columns[name]
		if index >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[index])
	}
	observations := make([]CertificateObservation, 0, len(rows)-1)
	for rowNumber, row := range rows[1:] {
		profileID := value(row, "policyid")
		if _, wanted := profiles[profileID]; !wanted {
			continue
		}
		deviceID := value(row, "deviceid")
		serial := value(row, "serialnumber")
		if deviceID == "" || serial == "" {
			return nil, fmt.Errorf("mdm: Intune certificate report row %d for configured profile %q lacks exact device or certificate serial", rowNumber+2, profileID)
		}
		validToRaw := value(row, "validto")
		validTo := parseMDMTime(validToRaw)
		if validToRaw != "" && validTo.IsZero() {
			return nil, fmt.Errorf("mdm: Intune certificate report row %d has an invalid ValidTo timestamp", rowNumber+2)
		}
		observations = append(observations, CertificateObservation{
			MDMDeviceID:  deviceID,
			PolicyID:     profileID,
			SerialNumber: serial,
			Status:       value(row, "certificatestatus"),
			ValidTo:      validTo,
		})
	}
	return observations, nil
}

func exactProfileSet(profileIDs []string) map[string]struct{} {
	out := make(map[string]struct{}, len(profileIDs))
	for _, profileID := range profileIDs {
		if profileID = strings.TrimSpace(profileID); profileID != "" {
			out[profileID] = struct{}{}
		}
	}
	return out
}

// AttachIntuneCertificateEvidence marks the report as observed for every
// Intune device and attaches only rows whose exact DeviceId matches. A device
// with no row remains an explicit observed-empty result for later comparison
// with the exact issued serial.
func AttachIntuneCertificateEvidence(devices []Device, evidence []CertificateObservation) {
	byDevice := make(map[string][]CertificateObservation)
	for _, observation := range evidence {
		deviceID := strings.TrimSpace(observation.MDMDeviceID)
		if deviceID != "" {
			byDevice[deviceID] = append(byDevice[deviceID], observation)
		}
	}
	for index := range devices {
		if devices[index].MDM != MDMIntune {
			continue
		}
		devices[index].InstallObserved = true
		devices[index].Certificates = append([]CertificateObservation(nil), byDevice[devices[index].MDMDeviceID]...)
		devices[index].InstallDetail = "Intune CertificatesByRAPolicy report completed for the configured SCEP profile; " +
			"the control plane must compare its rows with the exact issued serial."
	}
}
