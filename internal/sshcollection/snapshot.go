// SPDX-License-Identifier: BUSL-1.1

package sshcollection

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"
)

const Profile = "ssh-trust-read-v1"
const MaxPublicFileBytes = 256 << 10
const MaxSnapshotFileBytes = 1 << 20

// Snapshot is the fixed remote helper's public-only output. Authentication
// credentials, private HostKey files and arbitrary configuration are absent.
type Snapshot struct {
	Version    int                 `json:"version"`
	Profile    string              `json:"profile"`
	ConfigPath string              `json:"config_path"`
	Settings   map[string][]string `json:"settings"`
	Files      []PublicFile        `json:"files"`
}
type PublicFile struct {
	Path  string `json:"path"`
	Kind  string `json:"kind"`
	State string `json:"state"`
	Data  []byte `json:"data,omitempty"`
}

var settingKeys = map[string]bool{"trustedusercakeys": true, "revokedkeys": true, "authorizedprincipalsfile": true, "authorizedkeysfile": true, "hostcertificate": true}

func DecodeSnapshot(raw []byte) (Snapshot, error) {
	var out Snapshot
	if len(raw) == 0 || len(raw) > MaxReportBytes {
		return out, errors.New("SSH public snapshot exceeds its bound")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&out); err != nil {
		return out, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return out, errors.New("SSH public snapshot has trailing JSON")
	}
	return out, out.Validate()
}
func publicPath(raw string) bool {
	return len(raw) <= 4096 && path.IsAbs(raw) && path.Clean(raw) == raw && !strings.ContainsAny(raw, "\x00\r\n")
}
func (s Snapshot) Validate() error {
	if s.Version != 1 || s.Profile != Profile || !publicPath(s.ConfigPath) || len(s.Settings) > len(settingKeys) || len(s.Files) > 66 {
		return errors.New("SSH collection helper profile or snapshot shape is invalid")
	}
	for key := range settingKeys {
		values, ok := s.Settings[key]
		if !ok || len(values) == 0 {
			return errors.New("SSH helper omitted required effective-setting coverage")
		}
		if key != "hostcertificate" && key != "authorizedkeysfile" && len(values) != 1 {
			return errors.New("SSH helper returned conflicting scalar settings")
		}
	}
	size := 0
	for key, values := range s.Settings {
		if !settingKeys[key] || len(values) > 64 {
			return errors.New("SSH helper returned a setting outside its read-only profile")
		}
		for _, value := range values {
			if value == "" || (value == "none" && len(values) != 1) {
				return errors.New("SSH helper returned empty or conflicting setting coverage")
			}
			size += len(value)
			if len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
				return errors.New("SSH helper setting exceeds its text bound")
			}
		}
	}
	if size > 64<<10 {
		return errors.New("SSH helper settings exceed their total bound")
	}
	allowed := map[string]string{}
	for key, kind := range map[string]string{"trustedusercakeys": "ca", "revokedkeys": "revocations", "hostcertificate": "host_certificate"} {
		for _, value := range s.Settings[key] {
			if value != "none" && value != "" {
				if prior, ok := allowed[value]; ok && prior != kind {
					return errors.New("one SSH public file has conflicting roles")
				}
				allowed[value] = kind
			}
		}
	}
	seen := map[string]bool{}
	total := 0
	for _, file := range s.Files {
		kind, declared := allowed[file.Path]
		if !declared || seen[file.Path] || kind != file.Kind || file.Path == "" {
			return errors.New("SSH helper returned an undeclared or duplicate public file")
		}
		seen[file.Path] = true
		if len(file.Path) > 4096 || strings.ContainsAny(file.Path, "\x00\r\n") {
			return errors.New("SSH helper public path exceeds its bound")
		}
		switch file.State {
		case "read":
			if !publicPath(file.Path) || len(file.Data) > MaxPublicFileBytes {
				return errors.New("SSH public read exceeds its path/byte bound")
			}
			total += len(file.Data)
		case "missing", "unreadable", "too_large", "not_allowed", "invalid_public_material", "relative_path":
			if len(file.Data) != 0 {
				return errors.New("an unreadable SSH public file cannot carry bytes")
			}
		default:
			return errors.New("SSH helper public file state is unknown")
		}
		if bytes.Contains(file.Data, []byte("PRIVATE KEY")) {
			return errors.New("SSH helper returned forbidden private material")
		}
	}
	if total > MaxSnapshotFileBytes {
		return errors.New("SSH public files exceed their total bound")
	}
	for file := range allowed {
		if !seen[file] {
			return errors.New("SSH helper omitted a configured public file instead of reporting its coverage")
		}
	}
	return nil
}
func (s Snapshot) ReadPublicFile(name string) ([]byte, string) {
	for _, file := range s.Files {
		if file.Path == name {
			state := file.State
			if state == "too_large" || state == "not_allowed" || state == "invalid_public_material" {
				state = "unreadable"
			}
			return file.Data, state
		}
	}
	return nil, "missing"
}
