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
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/adcsdb"
)

// A162: the relay-executed AD CS CA database read. A domain-joined Windows relay
// runs certutil -view against one CA, parses every row with the same parser the
// ingest route uses, and reports the per-disposition summary. No certificate,
// and no issued, revoked or denied row's subject or requester, leaves the
// relay. N1-L2: the requests the CA holds for a manager's approval leave it as
// an operator needs them to decide one (request id, template, requested name,
// requester), newest first and bounded. The control plane records it as the
// CA's database observation.

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

// MaxADCSPendingRequests bounds the pending requests one read reports (N1-L2).
const MaxADCSPendingRequests = 500

// maxADCSPendingField bounds each reported field of a pending request.
const maxADCSPendingField = 256

// ADCSPendingRequest is one request the CA holds for a manager's approval,
// with what an operator needs to decide it (N1-L2).
type ADCSPendingRequest struct {
	RequestID  int    `json:"request_id"`
	Template   string `json:"template,omitempty"`
	CommonName string `json:"common_name,omitempty"`
	Requester  string `json:"requester,omitempty"`
}

// ADCSDatabaseReport is what returns: the counts, and the pending requests
// (N1-L2) newest first, at most MaxADCSPendingRequests; PendingTruncated says
// the CA holds more.
type ADCSDatabaseReport struct {
	CAConfig         string               `json:"ca_config"`
	Summary          adcsdb.DBSummary     `json:"summary"`
	RowsRead         int                  `json:"rows_read"`
	RowsRejected     int                  `json:"rows_rejected"`
	Pending          []ADCSPendingRequest `json:"pending,omitempty"`
	PendingTruncated bool                 `json:"pending_truncated,omitempty"`
}

// PendingListed reports whether a report lists the CA's pending requests: a
// relay from before N1-L2 counts them without listing them.
func (r ADCSDatabaseReport) PendingListed() bool {
	return r.Summary.Pending == 0 || len(r.Pending) > 0
}

// pendingRequests is the CA's pending requests, newest first and bounded.
func pendingRequests(rows []adcsdb.DBRow) ([]ADCSPendingRequest, bool) {
	var out []ADCSPendingRequest
	for _, row := range rows {
		if row.Disposition == adcsdb.DispositionPending && row.RequestID > 0 {
			out = append(out, ADCSPendingRequest{RequestID: row.RequestID, Template: clipPendingField(row.Template),
				CommonName: clipPendingField(row.Subject), Requester: clipPendingField(row.Requester)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RequestID > out[j].RequestID })
	if len(out) > MaxADCSPendingRequests {
		return out[:MaxADCSPendingRequests], true
	}
	return out, false
}

// clipPendingField keeps a field printable and bounded, cut on a rune.
func clipPendingField(v string) string {
	v = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(v))
	for len(v) > maxADCSPendingField {
		_, size := utf8.DecodeLastRuneInString(v)
		v = v[:len(v)-size]
	}
	return v
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
	case len(r.Pending) > MaxADCSPendingRequests || len(r.Pending) > s.Pending:
		return errors.New("relay: CA database report lists more pending requests than it counts")
	case r.PendingTruncated != (len(r.Pending) == MaxADCSPendingRequests && s.Pending > MaxADCSPendingRequests):
		return errors.New("relay: CA database report's pending list is cut short where it should not be, or whole where it should not be")
	case len(r.Pending) > 0 && !r.PendingTruncated && len(r.Pending) != s.Pending:
		return errors.New("relay: CA database report lists fewer pending requests than it counts")
	}
	seen := map[int]bool{}
	for i, p := range r.Pending {
		switch {
		case p.RequestID <= 0 || seen[p.RequestID]:
			return errors.New("relay: CA database report lists a pending request without a unique request id")
		case i > 0 && p.RequestID > r.Pending[i-1].RequestID:
			return errors.New("relay: CA database report's pending requests are not newest first")
		case p.Template != clipPendingField(p.Template) || p.CommonName != clipPendingField(p.CommonName) || p.Requester != clipPendingField(p.Requester):
			return errors.New("relay: CA database report lists a pending request field that is not printable and bounded")
		}
		seen[p.RequestID] = true
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
	pending, truncated := pendingRequests(parsed)
	detail, err := json.Marshal(ADCSDatabaseReport{CAConfig: intent.CAConfig, Summary: adcsdb.Summarize(parsed), RowsRead: len(rows),
		RowsRejected: rejected, Pending: pending, PendingTruncated: truncated})
	if err != nil {
		report(ctx, ch, job, OutcomeFailed, "the CA database summary could not be encoded")
		return false
	}
	report(ctx, ch, job, OutcomeExecuted, string(detail))
	return true
}

// certutilPageRows is how many request ids one paged read covers (A162-L1).
var certutilPageRows = 100_000

// certutilOutputBound is one certutil read's byte bound.
var certutilOutputBound int64 = maxCertutilOutputBytes

// errCertutilOutputBound is a read whose output exceeded the byte bound.
var errCertutilOutputBound = errors.New("relay: certutil output exceeds the byte bound")

// readCertutilView runs certutil -config <ca> -view -out <columns> csv,
// bounded in time as well as bytes and rows. A162-L1: a database whose rows
// exceed one read's byte bound is read again in pages of request ids, each
// page under the bound, so a large CA is summarized instead of refused.
func readCertutilView(ctx context.Context, certutil, caConfig string) ([]map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, certutilTimeout)
	defer cancel()
	rows, err := readCertutilCSV(ctx, certutil, "-config", caConfig, "-view", "-out", certutilViewColumns, "csv")
	if !errors.Is(err, errCertutilOutputBound) {
		return rows, err
	}
	return readCertutilViewPaged(ctx, certutil, caConfig)
}

// readCertutilViewPaged lists the database's request ids (a small read: one
// column), then reads the rows in ranges of certutilPageRows ids with
// -restrict "RequestID>lo,RequestID<=hi"; a range whose output still exceeds
// the bound is halved. A row that names no request id is kept as the id list
// read it, so the parser counts it as rejected instead of losing it.
func readCertutilViewPaged(ctx context.Context, certutil, caConfig string) ([]map[string]string, error) {
	idRows, err := readCertutilCSV(ctx, certutil, "-config", caConfig, "-view", "-out", "RequestID", "csv")
	if err != nil {
		return nil, err
	}
	var rows []map[string]string
	ids := make([]int, 0, len(idRows))
	seen := map[int]bool{}
	for _, r := range idRows {
		id := adcsdb.RequestIDOf(r)
		switch {
		case id <= 0:
			rows = append(rows, r)
		case !seen[id]:
			seen[id] = true
			ids = append(ids, id)
		}
	}
	sort.Ints(ids)
	var readRange func(ids []int, lo int) error
	readRange = func(ids []int, lo int) error {
		if len(ids) == 0 {
			return nil
		}
		hi := ids[len(ids)-1]
		page, err := readCertutilCSV(ctx, certutil, "-config", caConfig, "-restrict", "RequestID>"+strconv.Itoa(lo)+",RequestID<="+strconv.Itoa(hi),
			"-view", "-out", certutilViewColumns, "csv")
		if errors.Is(err, errCertutilOutputBound) && len(ids) > 1 {
			half := len(ids) / 2
			if err := readRange(ids[:half], lo); err != nil {
				return err
			}
			return readRange(ids[half:], ids[half-1])
		}
		if err != nil {
			return err
		}
		rows = append(rows, page...)
		if len(rows) > maxCertutilRows {
			return errors.New("relay: the CA database exceeds the row bound")
		}
		return nil
	}
	for start := 0; start < len(ids); start += certutilPageRows {
		end := start + certutilPageRows
		if end > len(ids) {
			end = len(ids)
		}
		lo := 0
		if start > 0 {
			lo = ids[start-1]
		}
		if err := readRange(ids[start:end], lo); err != nil {
			return nil, err
		}
	}
	return rows, nil
}

// runCertutil runs one certutil action. Its output is not read: what reaches
// the control plane is the CA database read back afterwards.
func runCertutil(ctx context.Context, certutil string, args ...string) error {
	return exec.CommandContext(ctx, certutil, args...).Run() // #nosec G204 -- reviewed SEC-005 argv: fixed action flags built here; the binary is operator-configured and every value is validated as one non-option argument (CWE-78)
}

// readCertutilCSV runs certutil with a fixed argument vector and reads its CSV
// output, bounded in bytes and rows; the caller bounds the time.
func readCertutilCSV(ctx context.Context, certutil string, args ...string) ([]map[string]string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, certutil, args...) // #nosec G204 -- reviewed SEC-005 argv: fixed flags built by this package; the binary is operator-configured and every value is validated as one non-option argument (CWE-78)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	counted := &countingReader{r: io.LimitReader(stdout, certutilOutputBound+1)}
	rows, parseErr := parseCertutilCSV(counted)
	if counted.n > certutilOutputBound {
		// Whatever the parser made of the cut output, the read is over the
		// bound (A162-L1 pages it).
		parseErr = errCertutilOutputBound
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
