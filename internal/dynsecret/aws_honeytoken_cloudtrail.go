// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/crypto/secret"
)

const awsCloudTrailTarget = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents"

var awsAccessKeyID = regexp.MustCompile(`^[A-Z0-9]{16,128}$`)

// AWSHoneyCloudTrailConfig scopes one lookup client to one AWS account/Region.
// IAM and CloudTrail endpoints are separate so operators can grant monitoring
// through an independent, short-lived role rather than the IAM writer.
type AWSHoneyCloudTrailConfig struct {
	Endpoint        string
	HTTPClient      HTTPDoer
	Region          string
	AccountID       string
	AccessKeyID     string
	SecretAccessKey []byte
	SessionToken    []byte
}

type AWSHoneyCloudTrail struct {
	query     *AWSIAMBackend
	accountID string
	region    string
}

type AWSHoneyUse struct {
	EventID         string    `json:"event_id"`
	AccessKeyID     string    `json:"access_key_id"`
	AccountID       string    `json:"account_id"`
	Region          string    `json:"region"`
	EventSource     string    `json:"event_source"`
	EventName       string    `json:"event_name"`
	SourceIPAddress string    `json:"source_ip_address"`
	UserAgent       string    `json:"user_agent"`
	ErrorCode       string    `json:"error_code,omitempty"`
	EventTime       time.Time `json:"event_time"`
}

func NewAWSHoneyCloudTrail(cfg AWSHoneyCloudTrailConfig) (*AWSHoneyCloudTrail, error) {
	if !awsAccountID.MatchString(cfg.AccountID) || strings.TrimSpace(cfg.Region) == "" {
		return nil, errors.New("aws honeytoken: CloudTrail account and region are required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://cloudtrail." + cfg.Region + ".amazonaws.com"
	}
	query, err := NewAWSIAMBackend(AWSIAMConfig{
		Endpoint: cfg.Endpoint, HTTPClient: cfg.HTTPClient, Region: cfg.Region,
		AccessKeyID: cfg.AccessKeyID, SecretAccessKey: cfg.SecretAccessKey,
		SessionToken: cfg.SessionToken,
	})
	if err != nil {
		return nil, fmt.Errorf("aws honeytoken: initialize CloudTrail query: %w", err)
	}
	return &AWSHoneyCloudTrail{query: query, accountID: cfg.AccountID, region: cfg.Region}, nil
}

func (c *AWSHoneyCloudTrail) Close() { c.query.Close() }

// LookupManagementPage returns at most one 50-event CloudTrail page. The caller
// must retain its time window across NextToken pages, rate limit to CloudTrail's
// per-account/per-Region quota, and persist the cursor only after all events are
// durably projected. LookupEvents covers management events in one Region and
// never claims data-event or global delivery completeness.
func (c *AWSHoneyCloudTrail) LookupManagementPage(ctx context.Context, keyID string, start, end time.Time, nextToken string) ([]AWSHoneyUse, string, error) {
	if !awsAccessKeyID.MatchString(keyID) || start.IsZero() || end.IsZero() || !start.Before(end) || end.Sub(start) > 90*24*time.Hour || len(nextToken) > 4096 {
		return nil, "", errors.New("aws honeytoken: invalid CloudTrail lookup bounds")
	}
	payload := struct {
		LookupAttributes []struct {
			AttributeKey   string `json:"AttributeKey"`
			AttributeValue string `json:"AttributeValue"`
		} `json:"LookupAttributes"`
		StartTime int64  `json:"StartTime"`
		EndTime   int64  `json:"EndTime"`
		Max       int    `json:"MaxResults"`
		Next      string `json:"NextToken,omitempty"`
	}{StartTime: start.Unix(), EndTime: end.Unix(), Max: 50, Next: nextToken}
	payload.LookupAttributes = append(payload.LookupAttributes, struct {
		AttributeKey   string `json:"AttributeKey"`
		AttributeValue string `json:"AttributeValue"`
	}{"AccessKeyId", keyID})
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.query.endpoint+"/", bytes.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	request.Header.Set("Content-Type", "application/x-amz-json-1.1")
	request.Header.Set("X-Amz-Target", awsCloudTrailTarget)
	c.query.signV4(request, body, c.query.now().UTC(), "cloudtrail")
	response, err := c.query.doer.Do(request)
	if err != nil {
		return nil, "", fmt.Errorf("aws honeytoken: CloudTrail lookup: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	limit := cloudhttp.MaxBodyBytes
	if response.StatusCode/100 != 2 {
		limit = cloudhttp.MaxErrorBytes
	}
	raw, err := secret.ReadBounded(response.Body, limit)
	if err != nil {
		return nil, "", err
	}
	defer secret.Wipe(raw)
	if response.StatusCode/100 != 2 {
		return nil, "", &cloudhttp.StatusError{StatusCode: response.StatusCode}
	}
	var page struct {
		Events []struct {
			ID         string  `json:"EventId"`
			Name       string  `json:"EventName"`
			Source     string  `json:"EventSource"`
			AccessKey  string  `json:"AccessKeyId"`
			EventTime  float64 `json:"EventTime"`
			CloudTrail string  `json:"CloudTrailEvent"`
		} `json:"Events"`
		NextToken string `json:"NextToken"`
	}
	if err := json.Unmarshal(raw, &page); err != nil || len(page.Events) > 50 || len(page.NextToken) > 4096 {
		return nil, "", errors.New("aws honeytoken: malformed CloudTrail page")
	}
	uses := make([]AWSHoneyUse, 0, len(page.Events))
	for _, item := range page.Events {
		var event struct {
			EventID            string `json:"eventID"`
			EventTime          string `json:"eventTime"`
			EventSource        string `json:"eventSource"`
			EventName          string `json:"eventName"`
			AWSRegion          string `json:"awsRegion"`
			SourceIPAddress    string `json:"sourceIPAddress"`
			UserAgent          string `json:"userAgent"`
			ErrorCode          string `json:"errorCode"`
			RecipientAccountID string `json:"recipientAccountId"`
			UserIdentity       struct {
				AccountID   string `json:"accountId"`
				AccessKeyID string `json:"accessKeyId"`
			} `json:"userIdentity"`
		}
		if json.Unmarshal([]byte(item.CloudTrail), &event) != nil || item.ID == "" || item.ID != event.EventID || item.AccessKey != keyID || event.UserIdentity.AccessKeyID != keyID || event.UserIdentity.AccountID != c.accountID || event.RecipientAccountID != c.accountID || event.AWSRegion != c.region || item.Name != event.EventName || item.Source != event.EventSource {
			return nil, "", errors.New("aws honeytoken: CloudTrail event identity or account mismatch")
		}
		when, err := time.Parse(time.RFC3339, event.EventTime)
		outer := time.Unix(int64(item.EventTime), 0).UTC()
		if err != nil || when.Before(start.Add(-time.Second)) || when.After(end.Add(time.Second)) ||
			outer.Before(when.Add(-time.Second)) || outer.After(when.Add(time.Second)) {
			return nil, "", errors.New("aws honeytoken: CloudTrail event outside requested window")
		}
		uses = append(uses, AWSHoneyUse{
			EventID: event.EventID, AccessKeyID: keyID, AccountID: c.accountID, Region: c.region,
			EventSource: event.EventSource, EventName: event.EventName,
			SourceIPAddress: boundedAWSHoneyText(event.SourceIPAddress, 128),
			UserAgent:       boundedAWSHoneyText(event.UserAgent, 512),
			ErrorCode:       boundedAWSHoneyText(event.ErrorCode, 128), EventTime: when,
		})
	}
	return uses, page.NextToken, nil
}

func boundedAWSHoneyText(value string, maximum int) string {
	var clean strings.Builder
	clean.Grow(min(len(value), maximum))
	for len(value) > 0 && clean.Len() < maximum {
		r, size := utf8.DecodeRuneInString(value)
		value = value[size:]
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if clean.Len()+utf8.RuneLen(r) > maximum {
			break
		}
		clean.WriteRune(r)
	}
	return clean.String()
}
