// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/objectstore"
	"trstctl.com/trstctl/internal/store"
)

// N4: the decoy monitor also reads the log files a CloudTrail trail delivers
// to S3. An organization trail holds every account in the organization and a
// trail that logs data events holds them too, so a decoy key used against an
// S3 object, or from an account other than its own, is found; LookupEvents
// finds neither.
const (
	// awsHoneyTrailTick is how often the leader checks which trails are due;
	// each trail is read at its account attachment's poll interval.
	awsHoneyTrailTick = 30 * time.Second
	// awsHoneyTrailMaxObjectBytes bounds one compressed log file; a larger one
	// is recorded as refused, never read in part.
	awsHoneyTrailMaxObjectBytes int64 = 64 << 20
	// awsHoneyTrailMaxReadsPerPass bounds the files one pass reads per trail;
	// what it leaves, the next pass reads.
	awsHoneyTrailMaxReadsPerPass = 2000
	awsHoneyTrailMaxAccounts     = 10000
	awsHoneyTrailMaxRegions      = 64
	awsHoneyTrailMaxPages        = 50
)

// awsHoneyTrailClock remembers when each trail was last read, on this leader.
type awsHoneyTrailClock struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func (c *awsHoneyTrailClock) due(key string, now time.Time, every time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last == nil {
		c.last = map[string]time.Time{}
	}
	if last, ok := c.last[key]; ok && now.Sub(last) < every {
		return false
	}
	c.last[key] = now
	return true
}

// RunAWSHoneyTrails reads every attached trail's new log files, on the leader.
func (s *Server) RunAWSHoneyTrails(ctx context.Context) {
	if !s.awsHoneyAccounts.hasTrails() {
		return
	}
	ticker := time.NewTicker(awsHoneyTrailTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := s.ReadAWSHoneyTrailsOnce(ctx); err != nil && s.logger != nil {
				s.logger.Warn("an AWS decoy trail could not be read", slog.String("error", err.Error()))
			}
		}
	}
}

// ReadAWSHoneyTrailsOnce reads each attached trail whose poll interval has
// passed and reports how many log files it recorded.
func (s *Server) ReadAWSHoneyTrailsOnce(ctx context.Context) (int, error) {
	if s.store == nil || s.orch == nil {
		return 0, nil
	}
	now := time.Now().UTC()
	total := 0
	var errs []error
	for _, tenantID := range s.awsHoneyAccounts.tenants() {
		for _, account := range s.awsHoneyAccounts.trailAccounts(tenantID) {
			if !s.awsHoneyTrailClock.due(tenantID+"\x00"+account.cfg.ID, now, account.interval) {
				continue
			}
			n, err := s.readAWSHoneyTrail(ctx, tenantID, account, now)
			total += n
			if err != nil {
				errs = append(errs, fmt.Errorf("trail of AWS account attachment %s: %w", account.cfg.ID, err))
			}
		}
	}
	return total, errors.Join(errs...)
}

// readAWSHoneyTrail reads one trail's unread log files from today's and
// yesterday's day folders (UTC) of every account and Region it holds.
func (s *Server) readAWSHoneyTrail(ctx context.Context, tenantID string, account *awsHoneyProvider, now time.Time) (int, error) {
	decoys, err := s.store.AWSHoneyTrailDecoyKeys(ctx, tenantID)
	if err != nil || len(decoys) == 0 {
		return 0, err
	}
	keys := make(map[string]bool, len(decoys))
	for key := range decoys {
		keys[key] = true
	}
	trail := account.cfg.Trail
	bucket, err := account.openTrail(ctx)
	if err != nil {
		return 0, err
	}
	defer bucket.Destroy()
	accountsPrefix, err := dynsecret.AWSTrailAccountsPrefix(trail.OrganizationID)
	if err != nil {
		return 0, err
	}
	accounts := append([]string(nil), trail.Accounts...)
	if len(accounts) == 0 {
		if accounts, err = bucket.ListDirs(ctx, accountsPrefix, awsHoneyTrailMaxAccounts); err != nil {
			return 0, err
		}
	}
	sort.Strings(accounts)
	read := 0
	for _, accountID := range accounts {
		if !dynsecret.ValidAWSAccountID(accountID) {
			continue
		}
		regions, err := bucket.ListDirs(ctx, accountsPrefix+accountID+"/CloudTrail/", awsHoneyTrailMaxRegions)
		if errors.Is(err, objectstore.ErrNotFound) {
			continue
		}
		if err != nil {
			return read, err
		}
		for _, region := range regions {
			if !dynsecret.ValidAWSTrailRegion(region) {
				continue
			}
			for _, day := range []time.Time{now.Add(-24 * time.Hour), now} {
				folder, err := dynsecret.AWSTrailDayFolder(accountsPrefix, accountID, region, day)
				if err != nil {
					return read, err
				}
				n, err := s.readAWSHoneyTrailFolder(ctx, tenantID, account.cfg.ID, bucket, folder, decoys, keys, awsHoneyTrailMaxReadsPerPass-read)
				read += n
				if err != nil {
					return read, err
				}
				if read >= awsHoneyTrailMaxReadsPerPass {
					return read, nil
				}
			}
		}
	}
	return read, nil
}

// readAWSHoneyTrailFolder records up to budget unread log files of one day
// folder, oldest name first.
func (s *Server) readAWSHoneyTrailFolder(ctx context.Context, tenantID, configID string, bucket *objectstore.S3, folder string,
	decoys map[string]string, keys map[string]bool, budget int) (int, error) {
	var names []string
	after := ""
	for page := 0; page < awsHoneyTrailMaxPages; page++ {
		objects, more, err := bucket.ListAfter(ctx, folder, after, 1000)
		if err != nil {
			return 0, err
		}
		for _, object := range objects {
			if dynsecret.AWSTrailLogFileName(object.Name) {
				names = append(names, object.Name)
			}
			after = object.Name
		}
		if !more || len(objects) == 0 {
			break
		}
	}
	done, err := s.store.AWSHoneyTrailObjectsRead(ctx, tenantID, configID, names)
	if err != nil {
		return 0, err
	}
	read := 0
	for _, name := range names {
		if done[name] {
			continue
		}
		if read >= budget {
			break
		}
		scan, err := s.scanAWSHoneyTrailObject(ctx, bucket, configID, name, decoys, keys)
		if errors.Is(err, objectstore.ErrNotFound) {
			continue // gone since the listing; nothing to record
		}
		if err != nil {
			return read, err
		}
		if err := s.orch.RecordAWSHoneyTrailObject(ctx, tenantID, scan); err != nil {
			return read, err
		}
		read++
	}
	return read, nil
}

// scanAWSHoneyTrailObject reads one log file and returns its record. A file
// larger than the bound, or one that is not a CloudTrail log file, is recorded
// as refused with the reason, so it is never read in part. Any other failure
// to fetch it is returned and records nothing, so the next pass reads it.
func (s *Server) scanAWSHoneyTrailObject(ctx context.Context, bucket *objectstore.S3, configID, name string, decoys map[string]string, keys map[string]bool) (store.AWSHoneyTrailObjectScan, error) {
	scan := store.AWSHoneyTrailObjectScan{AccountConfigID: configID, ObjectKey: name, Uses: []store.AWSHoneyTrailUse{}}
	var body bytes.Buffer
	object, err := bucket.Get(ctx, name, &body, awsHoneyTrailMaxObjectBytes)
	if errors.Is(err, objectstore.ErrTooLarge) {
		scan.Refused = fmt.Sprintf("larger than %d bytes compressed", awsHoneyTrailMaxObjectBytes)
		return scan, nil
	}
	if err != nil {
		return store.AWSHoneyTrailObjectScan{}, err
	}
	scan.SizeBytes = object.Size
	uses, records, err := dynsecret.ScanCloudTrailLogFile(bytes.NewReader(body.Bytes()), keys, 0)
	if err != nil {
		scan.Refused = boundedRefusal(err.Error())
		return scan, nil
	}
	scan.Records, scan.UsesTotal = records, len(uses)
	for _, use := range uses {
		if len(scan.Uses) == store.MaxAWSHoneyTrailUsesPerObject {
			break
		}
		scan.Uses = append(scan.Uses, store.AWSHoneyTrailUse{
			HoneyID: decoys[use.AccessKeyID], EventID: use.EventID, AccountID: use.AccountID,
			RecipientAccountID: use.RecipientAccountID, Region: use.Region,
			EventSource: use.EventSource, EventName: use.EventName, EventCategory: use.EventCategory,
			SourceIPAddress: use.SourceIPAddress, UserAgent: use.UserAgent, ErrorCode: use.ErrorCode,
			EventTime: use.EventTime,
		})
	}
	return scan, nil
}

// boundedRefusal keeps a refusal within its 512-byte column, cut on a rune.
func boundedRefusal(text string) string {
	if len(text) <= 512 {
		return text
	}
	cut := 509
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut] + "..."
}
