// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/netsec"
)

// ObjectStore configures an S3-compatible object store (AWS S3, MinIO, or
// another service that speaks the S3 API) as the durable target for signed
// audit archive segments and scheduled report and evidence-pack artifacts
// (audit.archive_object_store) and for full backup sets
// (--full-backup-to-object-store). Credentials are read from private files
// only, never from the config file or the environment directly.
type ObjectStore struct {
	// Endpoint is the store's base URL, for example
	// https://s3.us-east-1.amazonaws.com or https://minio.internal:9000.
	Endpoint string `json:"endpoint,omitempty"`
	// Region signs requests; it defaults to us-east-1, which MinIO accepts.
	Region string `json:"region,omitempty"`
	Bucket string `json:"bucket,omitempty"`
	// Prefix is an optional deployment root every object is stored under, so
	// several deployments can share one bucket.
	Prefix string `json:"prefix,omitempty"`
	// PathStyle addresses <endpoint>/<bucket>/<key>, which MinIO and most
	// S3-compatible stores need; AWS S3 also accepts virtual-hosted requests.
	PathStyle             bool   `json:"path_style,omitempty"`
	AccessKeyID           string `json:"access_key_id,omitempty"`
	SecretAccessKeyFile   string `json:"secret_access_key_file,omitempty"`
	SessionTokenFile      string `json:"session_token_file,omitempty"`
	CAFile                string `json:"ca_file,omitempty"`
	AllowInsecureLoopback bool   `json:"allow_insecure_loopback,omitempty"`
	// Timeout bounds one call that moves no payload (default 30s); a call that
	// moves an object gets this plus one second per MiB.
	Timeout string `json:"timeout,omitempty"`
	// MaxInFlight bounds concurrent calls per process (default 8); a call over
	// the bound is refused at once rather than queued.
	MaxInFlight int `json:"max_in_flight,omitempty"`
}

// Configured reports whether any object-store setting is present.
func (o ObjectStore) Configured() bool { return o != ObjectStore{} }

// TimeoutDuration parses Timeout; an empty value means the default.
func (o ObjectStore) TimeoutDuration() (time.Duration, error) {
	if strings.TrimSpace(o.Timeout) == "" {
		return 0, nil
	}
	return time.ParseDuration(o.Timeout)
}

// applyObjectStoreEnv overlays TRSTCTL_OBJECT_STORE_*. Every exported
// ObjectStore field has a line here, enforced by
// TestEveryObjectStoreFieldHasEnvWiring.
func applyObjectStoreEnv(getenv func(string) string, o *ObjectStore) {
	setString(getenv, "TRSTCTL_OBJECT_STORE_ENDPOINT", &o.Endpoint)
	setString(getenv, "TRSTCTL_OBJECT_STORE_REGION", &o.Region)
	setString(getenv, "TRSTCTL_OBJECT_STORE_BUCKET", &o.Bucket)
	setString(getenv, "TRSTCTL_OBJECT_STORE_PREFIX", &o.Prefix)
	setBool(getenv, "TRSTCTL_OBJECT_STORE_PATH_STYLE", &o.PathStyle)
	setString(getenv, "TRSTCTL_OBJECT_STORE_ACCESS_KEY_ID", &o.AccessKeyID)
	setString(getenv, "TRSTCTL_OBJECT_STORE_SECRET_ACCESS_KEY_FILE", &o.SecretAccessKeyFile)
	setString(getenv, "TRSTCTL_OBJECT_STORE_SESSION_TOKEN_FILE", &o.SessionTokenFile)
	setString(getenv, "TRSTCTL_OBJECT_STORE_CA_FILE", &o.CAFile)
	setBool(getenv, "TRSTCTL_OBJECT_STORE_ALLOW_INSECURE_LOOPBACK", &o.AllowInsecureLoopback)
	setString(getenv, "TRSTCTL_OBJECT_STORE_TIMEOUT", &o.Timeout)
	setInt(getenv, "TRSTCTL_OBJECT_STORE_MAX_IN_FLIGHT", &o.MaxInFlight)
}

func validateObjectStore(o ObjectStore) []error {
	if !o.Configured() {
		return nil
	}
	var errs []error
	if endpoint := strings.TrimSpace(o.Endpoint); endpoint == "" {
		errs = append(errs, errors.New("object_store.endpoint is required when an object store is configured"))
	} else {
		if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(endpoint, o.AllowInsecureLoopback); err != nil {
			errs = append(errs, fmt.Errorf("object_store.endpoint %q: %w", endpoint, err))
		} else if u, err := url.Parse(strings.TrimRight(endpoint, "/")); err != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			errs = append(errs, fmt.Errorf("object_store.endpoint %q must be a bare scheme://host[:port]", endpoint))
		}
		if o.AllowInsecureLoopback && !netsec.IsInsecureLoopbackHTTPURL(endpoint) {
			errs = append(errs, errors.New("object_store.allow_insecure_loopback requires an http localhost/loopback endpoint"))
		}
		if o.CAFile != "" && netsec.IsInsecureLoopbackHTTPURL(endpoint) {
			errs = append(errs, errors.New("object_store.ca_file requires an https endpoint"))
		}
	}
	if strings.TrimSpace(o.Bucket) == "" {
		errs = append(errs, errors.New("object_store.bucket is required when an object store is configured"))
	}
	if prefix := o.Prefix; prefix != "" && (strings.HasPrefix(prefix, "/") || strings.Contains(prefix, "..") || strings.Contains(prefix, "\\")) {
		errs = append(errs, fmt.Errorf("object_store.prefix %q must be a relative path without \"..\"", prefix))
	}
	if strings.TrimSpace(o.AccessKeyID) == "" {
		errs = append(errs, errors.New("object_store.access_key_id is required when an object store is configured"))
	}
	if strings.TrimSpace(o.SecretAccessKeyFile) == "" {
		errs = append(errs, errors.New("object_store.secret_access_key_file is required when an object store is configured"))
	}
	if timeout, err := o.TimeoutDuration(); err != nil {
		errs = append(errs, fmt.Errorf("object_store.timeout: %w", err))
	} else if o.Timeout != "" && (timeout < time.Second || timeout > 10*time.Minute) {
		errs = append(errs, fmt.Errorf("object_store.timeout %s must be between 1s and 10m", timeout))
	}
	if o.MaxInFlight < 0 || o.MaxInFlight > 64 {
		errs = append(errs, fmt.Errorf("object_store.max_in_flight %d must be between 1 and 64 (0 means the default)", o.MaxInFlight))
	}
	return errs
}

// LoadObjectStore resolves only the object_store section, from the config
// file named by TRSTCTL_CONFIG_FILE and the TRSTCTL_OBJECT_STORE_* overlay,
// and validates only that section. One-shot tools such as `trstctl doctor`
// use it so an unrelated setting cannot keep them from reaching the store.
func LoadObjectStore(getenv func(string) string) (ObjectStore, error) {
	var section ObjectStore
	if path := getenv("TRSTCTL_CONFIG_FILE"); path != "" {
		data, err := os.ReadFile(path) // #nosec G304 -- the operator's own config file (CWE-22)
		if err != nil {
			return ObjectStore{}, fmt.Errorf("read config file %q: %w", path, err)
		}
		parsed, err := Parse(data)
		if err != nil {
			return ObjectStore{}, err
		}
		section = parsed.ObjectStore
	}
	applyObjectStoreEnv(getenv, &section)
	if errs := validateObjectStore(section); len(errs) > 0 {
		return ObjectStore{}, errors.Join(errs...)
	}
	return section, nil
}
