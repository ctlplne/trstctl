// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// N4: a trail's log files. CloudTrail delivers every event a trail logs —
// management events and, when the trail selects them, data events — as gzip
// JSON files ({"Records":[…]}) under
// AWSLogs/[<organization-id>/]<account-id>/CloudTrail/<region>/<yyyy>/<mm>/<dd>/
// in the trail's bucket. An organization trail holds every account in the
// organization. LookupEvents returns neither data events nor another account's
// events, so a decoy key used against a data-event resource, or logged in an
// account other than its own, is seen only here.

var (
	awsOrganizationID = regexp.MustCompile(`^o-[a-z0-9]{10,32}$`)
	awsTrailRegion    = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
)

// MaxCloudTrailLogFileBytes bounds one log file after decompression. CloudTrail
// delivers a file about every five minutes per account and Region; a file this
// large is refused and recorded, never read in part.
const MaxCloudTrailLogFileBytes int64 = 256 << 20

// AWSHoneyTrailUse is one record of a trail's log file that a decoy key made.
type AWSHoneyTrailUse struct {
	AWSHoneyUse
	// EventCategory is CloudTrail's Management or Data.
	EventCategory string `json:"event_category"`
	// RecipientAccountID is the account whose trail logged the event: the
	// decoy's own account, or another account whose resource the key reached.
	RecipientAccountID string `json:"recipient_account_id"`
}

// AWSTrailAccountsPrefix is the folder that holds a trail's per-account log
// folders: AWSLogs/<organization-id>/ for an organization trail, AWSLogs/ for
// one account's trail.
func AWSTrailAccountsPrefix(organizationID string) (string, error) {
	if organizationID == "" {
		return "AWSLogs/", nil
	}
	if !awsOrganizationID.MatchString(organizationID) {
		return "", fmt.Errorf("aws honeytoken: %q is not an AWS organization ID", organizationID)
	}
	return "AWSLogs/" + organizationID + "/", nil
}

// AWSTrailDayFolder is one account's and Region's log folder for one UTC day.
func AWSTrailDayFolder(accountsPrefix, accountID, region string, day time.Time) (string, error) {
	if !awsAccountID.MatchString(accountID) || !awsTrailRegion.MatchString(region) {
		return "", fmt.Errorf("aws honeytoken: %q/%q is not an account and Region", accountID, region)
	}
	return accountsPrefix + accountID + "/CloudTrail/" + region + "/" + day.UTC().Format("2006/01/02") + "/", nil
}

// ValidAWSAccountID reports whether id is a twelve-digit AWS account ID.
func ValidAWSAccountID(id string) bool { return awsAccountID.MatchString(id) }

// ValidAWSTrailRegion reports whether region is shaped like an AWS Region.
func ValidAWSTrailRegion(region string) bool { return awsTrailRegion.MatchString(region) }

type cloudTrailRecord struct {
	EventID            string `json:"eventID"`
	EventTime          string `json:"eventTime"`
	EventSource        string `json:"eventSource"`
	EventName          string `json:"eventName"`
	AWSRegion          string `json:"awsRegion"`
	SourceIPAddress    string `json:"sourceIPAddress"`
	UserAgent          string `json:"userAgent"`
	ErrorCode          string `json:"errorCode"`
	EventCategory      string `json:"eventCategory"`
	RecipientAccountID string `json:"recipientAccountId"`
	UserIdentity       struct {
		AccountID   string `json:"accountId"`
		AccessKeyID string `json:"accessKeyId"`
	} `json:"userIdentity"`
}

// ScanCloudTrailLogFile reads one gzip log file and returns the records whose
// userIdentity.accessKeyId is one of keys, with how many records it read. It
// streams the Records array, so a file is never held whole, and refuses a file
// that decompresses past maxBytes or is not a CloudTrail log file.
func ScanCloudTrailLogFile(r io.Reader, keys map[string]bool, maxBytes int64) ([]AWSHoneyTrailUse, int, error) {
	if maxBytes <= 0 || maxBytes > MaxCloudTrailLogFileBytes {
		maxBytes = MaxCloudTrailLogFileBytes
	}
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, 0, fmt.Errorf("aws honeytoken: log file is not gzip: %w", err)
	}
	defer func() { _ = gz.Close() }()
	limited := &io.LimitedReader{R: gz, N: maxBytes + 1}
	dec := json.NewDecoder(limited)
	tooLarge := func(err error) error {
		if limited.N <= 0 {
			return fmt.Errorf("aws honeytoken: log file decompresses past %d bytes", maxBytes)
		}
		return fmt.Errorf("aws honeytoken: malformed log file: %w", err)
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, 0, tooLarge(errors.Join(err, errors.New("no top-level object")))
	}
	var uses []AWSHoneyTrailUse
	records, sawRecords := 0, false
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, 0, tooLarge(err)
		}
		if key, _ := tok.(string); key != "Records" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				return nil, 0, tooLarge(err)
			}
			continue
		}
		if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
			return nil, 0, tooLarge(errors.Join(err, errors.New("the Records member is not an array")))
		}
		sawRecords = true
		for dec.More() {
			var record cloudTrailRecord
			if err := dec.Decode(&record); err != nil {
				return nil, 0, tooLarge(err)
			}
			records++
			if !keys[record.UserIdentity.AccessKeyID] {
				continue
			}
			use, ok := trailUse(record)
			if !ok {
				return nil, 0, fmt.Errorf("aws honeytoken: record %d of a decoy key is incomplete", records)
			}
			uses = append(uses, use)
		}
		if _, err := dec.Token(); err != nil {
			return nil, 0, tooLarge(err)
		}
	}
	if _, err := dec.Token(); err != nil || !sawRecords {
		return nil, 0, tooLarge(errors.Join(err, errors.New("no Records array")))
	}
	return uses, records, nil
}

func trailUse(r cloudTrailRecord) (AWSHoneyTrailUse, bool) {
	when, err := time.Parse(time.RFC3339, r.EventTime)
	if err != nil || r.EventID == "" || len(r.EventID) > 128 || !awsAccessKeyID.MatchString(r.UserIdentity.AccessKeyID) ||
		!awsTrailRegion.MatchString(r.AWSRegion) || r.EventSource == "" || r.EventName == "" ||
		(r.RecipientAccountID != "" && !awsAccountID.MatchString(r.RecipientAccountID)) ||
		(r.UserIdentity.AccountID != "" && !awsAccountID.MatchString(r.UserIdentity.AccountID)) {
		return AWSHoneyTrailUse{}, false
	}
	category := r.EventCategory
	switch category {
	case "Management", "Data", "Insight", "NetworkActivity":
	case "":
		category = "Management"
	default:
		category = boundedAWSHoneyText(category, 32)
	}
	return AWSHoneyTrailUse{
		AWSHoneyUse: AWSHoneyUse{
			EventID: boundedAWSHoneyText(r.EventID, 128), AccessKeyID: r.UserIdentity.AccessKeyID,
			AccountID: r.UserIdentity.AccountID, Region: r.AWSRegion,
			EventSource: boundedAWSHoneyText(r.EventSource, 128), EventName: boundedAWSHoneyText(r.EventName, 128),
			SourceIPAddress: boundedAWSHoneyText(r.SourceIPAddress, 128),
			UserAgent:       boundedAWSHoneyText(r.UserAgent, 512),
			ErrorCode:       boundedAWSHoneyText(r.ErrorCode, 128), EventTime: when.UTC(),
		},
		EventCategory: category, RecipientAccountID: r.RecipientAccountID,
	}, true
}

// AWSTrailLogFileName reports whether name is a CloudTrail log file in a day
// folder (…/<account>_CloudTrail_<region>_<yyyymmdd>T<hhmm>Z_<id>.json.gz).
func AWSTrailLogFileName(name string) bool {
	base := name[strings.LastIndex(name, "/")+1:]
	return strings.HasSuffix(base, ".json.gz") && strings.Contains(base, "_CloudTrail_")
}
