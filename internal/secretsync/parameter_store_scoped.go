// SPDX-License-Identifier: BUSL-1.1

package secretsync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// A202-L1: a Parameter Store destination reads its own state back. A scoped
// sync (A237) lists, compares and deletes its parameters, so a drift check
// finds a value changed outside trstctl and the next apply writes the source
// value again; and a delivery whose outcome was lost is settled by reading the
// parameter rather than writing it a second time. Values are read with
// WithDecryption, compared as SHA-256 digests or in constant time, and wiped:
// none leaves the pusher.

const (
	// parameterStorePageSize is GetParametersByPath's largest MaxResults.
	parameterStorePageSize = 10
	// parameterStoreMaxPages bounds one listing; a larger hierarchy is
	// reported as more than a plan reads.
	parameterStoreMaxPages = 1000
	// parameterStoreMaxName and parameterStoreMaxDepth are SSM's limits on a
	// parameter's full name and its hierarchy.
	parameterStoreMaxName  = 1011
	parameterStoreMaxDepth = 15
)

// parameterStoreText is a decrypted parameter value read into wipeable bytes.
type parameterStoreText []byte

func (t *parameterStoreText) UnmarshalText(text []byte) error {
	*t = append((*t)[:0], text...)
	return nil
}

// ScopedKeys: Parameter Store lists its parameters by path.
func (p *AWSParameterStorePusher) ScopedKeys() bool { return true }

// ReadsBack: a SecureString reads back with WithDecryption.
func (p *AWSParameterStorePusher) ReadsBack() bool { return true }

// ReconcilesReceiver: a lost delivery result is settled by a read.
func (p *AWSParameterStorePusher) ReconcilesReceiver() bool { return true }

// FlatKeys: parameters are hierarchical paths.
func (p *AWSParameterStorePusher) FlatKeys() bool { return false }

// ValidKey reports whether key can name a parameter under this target.
func (p *AWSParameterStorePusher) ValidKey(key string) error {
	return ParameterStoreValidKey(p.prefix, key)
}

// DigestOf is the digest ReadDigest returns for a parameter holding value.
func (p *AWSParameterStorePusher) DigestOf(value []byte) string { return crypto.SHA256Hex(value) }

// ParameterStoreValidKey reports whether key can name a parameter under
// prefix: letters, digits and _.-/ only, no empty path segment, at most 1011
// characters and 15 levels in all, and a first level that does not begin with
// aws or ssm, which AWS reserves.
func ParameterStoreValidKey(prefix, key string) error {
	key = strings.Trim(strings.TrimSpace(key), "/")
	if key == "" {
		return errors.New("secretsync: a parameter name needs a key")
	}
	name := "/" + key
	if prefix = strings.Trim(strings.TrimSpace(prefix), "/"); prefix != "" {
		name = "/" + prefix + "/" + key
	}
	if len(name) > parameterStoreMaxName {
		return fmt.Errorf("secretsync: a parameter name is at most %d characters", parameterStoreMaxName)
	}
	if strings.Contains(name, "//") {
		return errors.New("secretsync: a parameter name has no empty path segment")
	}
	if strings.Count(name, "/") > parameterStoreMaxDepth {
		return fmt.Errorf("secretsync: a parameter name is at most %d levels deep", parameterStoreMaxDepth)
	}
	for _, r := range name {
		if !parameterNameRune(r) {
			return fmt.Errorf("secretsync: a parameter name holds only letters, digits and _.-/, not %q", r)
		}
	}
	first, _, _ := strings.Cut(strings.TrimPrefix(name, "/"), "/")
	if lower := strings.ToLower(first); strings.HasPrefix(lower, "aws") || strings.HasPrefix(lower, "ssm") {
		return errors.New("secretsync: a parameter name cannot begin with aws or ssm")
	}
	return nil
}

// parameterNameRune reports whether r may appear in a parameter name.
func parameterNameRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	}
	return strings.ContainsRune("_.-/", r)
}

// call sends one SSM JSON API action and decodes a 2xx answer into out.
func (p *AWSParameterStorePusher) call(ctx context.Context, action string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint+"/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "AmazonSSM."+action)
	signAWSJSONRequest(req, body, p.now().UTC(), p.host, p.region, "ssm", p.accessKeyID, p.secretKey, p.sessionToken)
	return readJSON2xx(p.doer, req, out)
}

// rootPath is the hierarchy every key of this target lands under.
func (p *AWSParameterStorePusher) rootPath() string {
	if p.prefix == "" {
		return "/"
	}
	return "/" + p.prefix + "/"
}

// ListKeys returns the keys under prefix, sorted: GetParametersByPath,
// recursive and without decryption, so only names are read.
func (p *AWSParameterStorePusher) ListKeys(ctx context.Context, prefix string, limit int) ([]string, error) {
	path := p.ParameterName(prefix)
	if path != "/" {
		path = strings.TrimSuffix(path, "/")
	}
	root := p.rootPath()
	var keys []string
	token := ""
	for page := 0; ; page++ {
		if page >= parameterStoreMaxPages {
			return nil, ErrScopedListLimit
		}
		request := map[string]any{"Path": path, "Recursive": true, "WithDecryption": false, "MaxResults": parameterStorePageSize}
		if token != "" {
			request["NextToken"] = token
		}
		body, err := json.Marshal(request)
		if err != nil {
			return nil, err
		}
		var out struct {
			Parameters []struct {
				Name string `json:"Name"`
			} `json:"Parameters"`
			NextToken string `json:"NextToken"`
		}
		if err := p.call(ctx, "GetParametersByPath", body, &out); err != nil {
			return nil, err
		}
		for _, parameter := range out.Parameters {
			if key, under := strings.CutPrefix(parameter.Name, root); under && key != "" {
				keys = append(keys, key)
			}
		}
		if limit > 0 && len(keys) > limit {
			return nil, ErrScopedListLimit
		}
		if out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	slices.Sort(keys)
	return slices.Compact(keys), nil
}

// readValue reads a parameter's decrypted value; the caller wipes it.
func (p *AWSParameterStorePusher) readValue(ctx context.Context, key string) ([]byte, bool, error) {
	body, err := json.Marshal(map[string]any{"Name": p.ParameterName(key), "WithDecryption": true})
	if err != nil {
		return nil, false, err
	}
	var out struct {
		Parameter struct {
			Value parameterStoreText `json:"Value"`
		} `json:"Parameter"`
	}
	err = p.call(ctx, "GetParameter", body, &out)
	if isAWSMissingSecret(err) {
		return nil, false, nil
	}
	if err != nil {
		secret.Wipe(out.Parameter.Value)
		return nil, false, err
	}
	return out.Parameter.Value, true, nil
}

// ReadDigest reports whether the key's parameter exists and the SHA-256 of
// its value.
func (p *AWSParameterStorePusher) ReadDigest(ctx context.Context, key string) (bool, string, error) {
	value, found, err := p.readValue(ctx, key)
	if err != nil || !found {
		return found, "", err
	}
	defer secret.Wipe(value)
	return true, crypto.SHA256Hex(value), nil
}

// Delete removes the key's parameter; one already gone is not an error.
func (p *AWSParameterStorePusher) Delete(ctx context.Context, key string) error {
	body, err := json.Marshal(map[string]any{"Name": p.ParameterName(key)})
	if err != nil {
		return err
	}
	if err := p.call(ctx, "DeleteParameter", body, nil); err != nil && !isAWSMissingSecret(err) {
		return err
	}
	return nil
}

// ReconcileOperation compares the parameter with this command's value, in
// constant time; a missing parameter differs.
func (p *AWSParameterStorePusher) ReconcileOperation(ctx context.Context, key string, value []byte) (ReceiverReconciliation, error) {
	got, found, err := p.readValue(ctx, key)
	if err != nil {
		return ReceiverStateUnknown, err
	}
	if !found {
		return ReceiverStateDiffers, nil
	}
	defer secret.Wipe(got)
	if crypto.ConstantTimeEqual(got, value) {
		return ReceiverStateMatches, nil
	}
	return ReceiverStateDiffers, nil
}
