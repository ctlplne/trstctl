// SPDX-License-Identifier: BUSL-1.1
package awsiam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
)

// ChangeClient performs only explicitly selected IAM changes. Its caller must
// be the reviewed durable outbox worker, never a request handler or collector.
type ChangeClient struct{ client *Client }
type ChangeTarget struct {
	ARN, NativeID, Name string
	Kind                awspolicy.PrincipalKind
}
type ChangeReadback struct {
	KeyAbsent, PolicyMatches bool
	Postcondition            string
	CheckedAt                time.Time
}

func NewChangeClient(cfg Config) (*ChangeClient, error) {
	client, err := New(cfg)
	if err != nil {
		return nil, err
	}
	return &ChangeClient{client: client}, nil
}
func (c *ChangeClient) RevokeKey(ctx context.Context, target ChangeTarget, keyID string) (ChangeReadback, error) {
	if target.Kind != awspolicy.IAMUser || !validateName(keyID) {
		return ChangeReadback{}, errors.New("awsiam: exact IAM user key required")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	session := &captureSession{c: c.client}
	if err := session.verifyChangeTarget(ctx, target); err != nil {
		return ChangeReadback{}, err
	}
	exists, err := session.hasKey(ctx, target.Name, keyID)
	if err != nil {
		return ChangeReadback{}, err
	}
	postcondition := "already_absent"
	if exists {
		if _, err = session.query(ctx, "DeleteAccessKey", url.Values{"UserName": {target.Name}, "AccessKeyId": {keyID}}, true); err != nil && !missingIAM(err) {
			return ChangeReadback{}, err
		}
		postcondition = "deleted_and_read_back"
	}
	if err := session.verifyChangeTarget(ctx, target); err != nil {
		return ChangeReadback{}, err
	}
	exists, err = session.hasKey(ctx, target.Name, keyID)
	if err != nil {
		return ChangeReadback{}, err
	}
	if exists {
		return ChangeReadback{}, errors.New("awsiam: exact old key is still present after change")
	}
	return ChangeReadback{KeyAbsent: true, Postcondition: postcondition, CheckedAt: time.Now().UTC()}, nil
}
func (c *ChangeClient) PutOwnedDeny(ctx context.Context, target ChangeTarget, name string, document []byte) (ChangeReadback, error) {
	if !strings.HasPrefix(name, "trstctl-tighten-") || !validateName(name) || len(document) > 64<<10 {
		return ChangeReadback{}, errors.New("awsiam: owned restrictive policy required")
	}
	var proposed struct {
		Version   string
		Statement []struct {
			Effect   string
			Action   json.RawMessage
			Resource json.RawMessage
			Sid      string
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&proposed) != nil || proposed.Version != "2012-10-17" || len(proposed.Statement) == 0 {
		return ChangeReadback{}, errors.New("awsiam: invalid restrictive document")
	}
	for _, statement := range proposed.Statement {
		if statement.Effect != "Deny" {
			return ChangeReadback{}, errors.New("awsiam: this writer only creates explicit Deny policies")
		}
	}
	if _, err := awspolicy.Parse("reviewed-deny", document); err != nil {
		return ChangeReadback{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	session := &captureSession{c: c.client}
	if err := session.verifyChangeTarget(ctx, target); err != nil {
		return ChangeReadback{}, err
	}
	typ := "User"
	if target.Kind == awspolicy.IAMRole {
		typ = "Role"
	}
	params := url.Values{typ + "Name": {target.Name}, "PolicyName": {name}}
	before, err := session.inlinePolicy(ctx, typ, params)
	if err != nil && !missingIAM(err) {
		return ChangeReadback{}, err
	}
	if err == nil && !samePolicy(before, document) {
		return ChangeReadback{}, errors.New("awsiam: owned policy name already holds different content")
	}
	postcondition := "already_matches"
	if missingIAM(err) {
		params.Set("PolicyDocument", string(document))
		if _, err = session.query(ctx, "Put"+typ+"Policy", params, true); err != nil {
			return ChangeReadback{}, err
		}
		params.Del("PolicyDocument")
		postcondition = "written_and_read_back"
	}
	if err := session.verifyChangeTarget(ctx, target); err != nil {
		return ChangeReadback{}, err
	}
	after, err := session.inlinePolicy(ctx, typ, params)
	if err != nil {
		return ChangeReadback{}, err
	}
	if !samePolicy(after, document) {
		return ChangeReadback{}, errors.New("awsiam: restrictive policy readback differs")
	}
	return ChangeReadback{PolicyMatches: true, Postcondition: postcondition, CheckedAt: time.Now().UTC()}, nil
}
func (s *captureSession) verifyChangeTarget(ctx context.Context, target ChangeTarget) error {
	if !validateName(target.Name) || !validateName(target.NativeID) || len(target.ARN) > 2048 {
		return errors.New("awsiam: invalid immutable change target")
	}
	typ := "User"
	if target.Kind == awspolicy.IAMRole {
		typ = "Role"
	} else if target.Kind != awspolicy.IAMUser {
		return errors.New("awsiam: unsupported change principal")
	}
	result, err := s.call(ctx, "Get"+typ, url.Values{typ + "Name": {target.Name}})
	if err != nil {
		return err
	}
	native, err := result.child(typ)
	if err != nil {
		return err
	}
	arn, err := native.value("Arn")
	if err != nil || arn != target.ARN {
		return errors.New("awsiam: change target ARN drifted")
	}
	id, err := native.value(typ + "Id")
	if err != nil || id != target.NativeID {
		return errors.New("awsiam: immutable change principal ID drifted")
	}
	return nil
}
func (s *captureSession) hasKey(ctx context.Context, user, keyID string) (bool, error) {
	items, err := s.list(ctx, "ListAccessKeys", url.Values{"UserName": {user}}, "AccessKeyMetadata")
	if err != nil {
		return false, err
	}
	if len(items) > 2 {
		return false, errors.New("awsiam: native key count exceeds bound")
	}
	for _, item := range items {
		name, err := item.value("UserName")
		if err != nil || name != user {
			return false, errors.New("awsiam: key owner readback differs")
		}
		id, err := item.value("AccessKeyId")
		if err != nil {
			return false, err
		}
		if id == keyID {
			return true, nil
		}
	}
	return false, nil
}
func (s *captureSession) inlinePolicy(ctx context.Context, typ string, params url.Values) ([]byte, error) {
	response, err := s.call(ctx, "Get"+typ+"Policy", params)
	if err != nil {
		return nil, err
	}
	raw, err := response.value("PolicyDocument")
	if err != nil {
		return nil, err
	}
	return decodePolicy(raw)
}
func samePolicy(a, b []byte) bool {
	var left, right any
	return json.Unmarshal(a, &left) == nil && json.Unmarshal(b, &right) == nil && reflect.DeepEqual(left, right)
}
func missingIAM(err error) bool {
	var status *StatusError
	return errors.As(err, &status) && status.Status == http.StatusNotFound
}
