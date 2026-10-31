// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/adcsdb"
)

// A162: the relay-executed AD CS CA database read. A domain-joined Windows relay
// runs certutil -view against one CA, parses every row with the same parser the
// ingest route uses, and reports only the per-disposition summary: no subject,
// requester or certificate leaves the relay. The control plane records it as
// the CA's database observation.

// KindADCSDatabase is the relay-executed CA database read.
const KindADCSDatabase = "adcs.ca_database"

// CertutilPath is the certutil the relay runs for CA database work. Empty
// refuses the work: only a domain-joined Windows relay has certutil and the
// CA's read rights. cmd/trstctl-agent sets it from --adcs-certutil.
var CertutilPath = defaultCertutilPath()

func defaultCertutilPath() string {
	if runtime.GOOS == "windows" {
		return "certutil.exe"
	}
	return ""
}

const (
	maxCertutilOutputBytes = 64 << 20
	maxCertutilRows        = 1_000_000
	certutilTimeout        = 10 * time.Minute
	// certutilViewColumns names exactly the columns the summary reads. The
	// default view includes every issued certificate's binary, which would
	// spend the byte bound on bytes nobody reads.
	certutilViewColumns = "RequestID,Request.Disposition,SerialNumber,NotBefore,NotAfter,CommonName,CertificateTemplate,Request.RequesterName,Request.RevokedWhen"
)

// ADCSDatabaseIntent is the job payload: the CA to read, by certsrv's own
// HOST\CA-Name identifier, on one exact relay.
type ADCSDatabaseIntent struct {
	ID              string `json:"id"`
	CAConfig        string `json:"ca_config"`
	RequiredAgentID string `json:"required_agent_id"`
}

// ADCSDatabaseReport is what returns: counts only.
type ADCSDatabaseReport struct {
	CAConfig     string           `json:"ca_config"`
	Summary      adcsdb.DBSummary `json:"summary"`
	RowsRead     int              `json:"rows_read"`
	RowsRejected int              `json:"rows_rejected"`
}

// ValidateADCSDatabaseReport checks a relay's counts against the queued read:
// the same CA, and counts that add up, so a wrong or tampered report cannot
// record a breakdown no certutil output could produce.
func ValidateADCSDatabaseReport(intent ADCSDatabaseIntent, r ADCSDatabaseReport) error {
	s := r.Summary
	switch {
	case r.CAConfig != intent.CAConfig:
		return errors.New("relay: CA database report names a different CA than the queued read")
	case s.Issued < 0 || s.Pending < 0 || s.Revoked < 0 || s.Denied < 0 || s.Failed < 0 || s.Unknown < 0 || s.Unparsed < 0 || r.RowsRejected < 0:
		return errors.New("relay: CA database report has a negative count")
	case s.Issued+s.Pending+s.Revoked+s.Denied+s.Failed+s.Unknown != s.Total:
		return errors.New("relay: CA database dispositions do not add up to the total")
	case s.Unparsed > s.Issued:
		return errors.New("relay: CA database report has more unparsed expiries than issued rows")
	case r.RowsRead != s.Total+r.RowsRejected || r.RowsRead > maxCertutilRows:
		return errors.New("relay: CA database rows read do not match the parsed and rejected rows")
	}
	return nil
}

// ValidCAConfig reports whether s is a certsrv CA identifier certutil can be
// given as one argument: HOST\CA-Name, printable, not option-shaped.
func ValidCAConfig(s string) bool {
	if s == "" || len(s) > 256 || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "/") || !strings.Contains(s, `\`) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '"' {
			return false
		}
	}
	return true
}

func runADCSDatabase(ctx context.Context, ch Channel, job Job) bool {
	var intent ADCSDatabaseIntent
	if err := decodeJobPayload(job.Payload, &intent); err != nil || intent.ID == "" || intent.RequiredAgentID == "" || !ValidCAConfig(intent.CAConfig) {
		report(ctx, ch, job, OutcomeFailed, "job payload is not a CA database read for one certsrv CA")
		return false
	}
	if CertutilPath == "" {
		report(ctx, ch, job, OutcomeFailed, "this relay has no certutil; CA database reads need a domain-joined Windows relay")
		return false
	}
	rows, err := readCertutilView(ctx, CertutilPath, intent.CAConfig)
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "certutil could not read the CA database from this relay")
		return false
	}
	parsed := make([]adcsdb.DBRow, 0, len(rows))
	rejected := 0
	for _, fields := range rows {
		row, err := adcsdb.ParseDBRow(fields)
		if err != nil {
			// Counted, never dropped: a collection problem must not read as an
			// empty CA.
			rejected++
			continue
		}
		parsed = append(parsed, row)
	}
	detail, err := json.Marshal(ADCSDatabaseReport{CAConfig: intent.CAConfig, Summary: adcsdb.Summarize(parsed), RowsRead: len(rows), RowsRejected: rejected})
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "the CA database summary could not be encoded")
		return false
	}
	report(ctx, ch, job, OutcomeExecuted, string(detail))
	return true
}

// readCertutilView runs certutil -config <ca> -view -out <columns> csv with a
// fixed argument vector and reads its CSV output, bounded in bytes, rows and
// time.
func readCertutilView(ctx context.Context, certutil, caConfig string) ([]map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, certutilTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, certutil, "-config", caConfig, "-view", "-out", certutilViewColumns, "csv") // #nosec G204 -- reviewed SEC-005 argv: fixed flags; the binary is operator-configured and the CA identifier is validated as one non-option argument (CWE-78)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	counted := &countingReader{r: io.LimitReader(stdout, maxCertutilOutputBytes+1)}
	rows, parseErr := parseCertutilCSV(counted)
	if parseErr == nil && counted.n > maxCertutilOutputBytes {
		parseErr = errors.New("relay: certutil output exceeds the byte bound")
	}
	if parseErr != nil {
		// Stop certutil rather than drain output nobody will read.
		cancel()
	}
	waitErr := cmd.Wait()
	if parseErr != nil {
		return nil, parseErr
	}
	if waitErr != nil {
		return nil, waitErr
	}
	return rows, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func parseCertutilCSV(r io.Reader) ([]map[string]string, error) {
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	header, err := reader.Read()
	if err != nil {
		return nil, errors.New("relay: certutil printed no CSV header")
	}
	for i := range header {
		header[i] = strings.TrimSpace(strings.TrimPrefix(header[i], string(rune(0xFEFF))))
	}
	var rows []map[string]string
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			return rows, nil
		}
		if err != nil {
			return nil, err
		}
		if len(rows) >= maxCertutilRows {
			return nil, errors.New("relay: the CA database exceeds the row bound")
		}
		fields := make(map[string]string, len(header))
		for i, value := range record {
			if i < len(header) {
				fields[header[i]] = value
			}
		}
		rows = append(rows, fields)
	}
}
