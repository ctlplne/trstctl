// SPDX-License-Identifier: BUSL-1.1

// Package abi is the contract between a host (the control plane or a relay)
// and the first-party connector module running in the WASM sandbox: the
// operation the host asks the guest to run, the sandbox operations the guest
// asks the host to perform, and the sentinel errors that keep their identity
// across the boundary. It is plain data, compiled into both sides.
//
// The wire is JSON in guest linear memory:
//
//   - The host writes a Call into memory the guest allocated with
//     trstctl_alloc and invokes trstctl_call(ptr, len). The guest hands back a
//     Result through the host import result(ptr, len) before returning.
//   - While a call runs, every Sandbox operation the connector makes becomes a
//     SandboxOp the guest passes to the host import sandbox(ptr, len); the host
//     performs it through the same capability-gated sandbox an in-process
//     connector would get, keeps the SandboxResult, and the guest copies it out
//     with take(ptr, len).
//
// Beyond these, the guest imports only the WASI functions the Go runtime
// links. The host instantiates it with no arguments, no environment, no
// preopened directory (so no path resolves), discarded output and no socket:
// WASI gives it a clock, a random source and nothing else.
package abi

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"sort"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/native"
)

// Version is the contract version a Call carries; a guest refuses another.
const Version = 1

// Module and export names.
const (
	HostModule   = "trstctl_connector_host"
	ExportAlloc  = "trstctl_alloc"
	ExportFree   = "trstctl_free"
	ExportCall   = "trstctl_call"
	ImportResult = "result"
	ImportOp     = "sandbox"
	ImportTake   = "take"
)

// Bounds on what crosses the boundary in either direction.
const (
	MaxCallBytes   = 8 << 20
	MaxResultBytes = 1 << 20
	MaxOpBytes     = 32 << 20
	MaxBodyBytes   = 16 << 20
)

// Guest operations: one per connector method a host may invoke.
const (
	OpDeploy                  = "deploy"
	OpReadback                = "readback"
	OpPreview                 = "preview"
	OpRollback                = "rollback"
	OpRollbackLegacy          = "rollback_legacy"
	OpTakedown                = "takedown"
	OpReadTLSPosture          = "read_tls_posture"
	OpApplyTLSPosture         = "apply_tls_posture"
	OpGenerateApplianceKey    = "generate_appliance_key"
	OpInstallWithApplianceKey = "install_with_appliance_key"
)

// Call is what the host asks the guest to do: build Family's connector from
// Config and Credentials, exactly as native.Build would on the host, and run
// one operation on it.
type Call struct {
	Version     int               `json:"version"`
	Op          string            `json:"op"`
	Family      string            `json:"family"`
	Config      native.Target     `json:"config"`
	Credentials map[string][]byte `json:"credentials,omitempty"`

	Deployment          *connector.Deployment          `json:"deployment,omitempty"`
	TargetName          string                         `json:"target_name,omitempty"`
	Rollback            *connector.Rollback            `json:"rollback,omitempty"`
	Takedown            *connector.Takedown            `json:"takedown,omitempty"`
	Posture             *connector.TLSPosture          `json:"posture,omitempty"`
	ApplianceKeyRequest *connector.ApplianceKeyRequest `json:"appliance_key_request,omitempty"`
	ApplianceKey        *connector.ApplianceKey        `json:"appliance_key,omitempty"`
}

// Result is the guest's answer to a Call.
type Result struct {
	Installed    *connector.Installed    `json:"installed,omitempty"`
	Preview      *connector.Preview      `json:"preview,omitempty"`
	Posture      *connector.TLSPosture   `json:"posture,omitempty"`
	ApplianceKey *connector.ApplianceKey `json:"appliance_key,omitempty"`
	Error        *Error                  `json:"error,omitempty"`
}

// Error is an error that crossed the boundary: its text and the sentinel errors
// it matched on the side that produced it.
type Error struct {
	Message string   `json:"message"`
	Is      []string `json:"is,omitempty"`
}

// Sandbox operations a guest may ask the host to perform.
const (
	SandboxSend      = "send"
	SandboxReadFile  = "read_file"
	SandboxWriteFile = "write_file"
	SandboxExec      = "exec"
	SandboxHTTP      = "http"
)

// SandboxOp is one Sandbox operation the connector made inside the guest.
type SandboxOp struct {
	Op      string       `json:"op"`
	Target  string       `json:"target,omitempty"`
	Payload []byte       `json:"payload,omitempty"`
	Path    string       `json:"path,omitempty"`
	Data    []byte       `json:"data,omitempty"`
	Name    string       `json:"name,omitempty"`
	Args    []string     `json:"args,omitempty"`
	Request *HTTPRequest `json:"request,omitempty"`
}

// HTTPRequest is the part of an *http.Request a connector controls.
type HTTPRequest struct {
	Method string      `json:"method"`
	URL    string      `json:"url"`
	Header http.Header `json:"header,omitempty"`
	// HasBody distinguishes a request sent with an empty body from one sent
	// with none, as the connector built it.
	HasBody bool   `json:"has_body,omitempty"`
	Body    []byte `json:"body,omitempty"`
}

// SandboxResult is the host's answer to a SandboxOp.
type SandboxResult struct {
	Data     []byte        `json:"data,omitempty"`
	Response *HTTPResponse `json:"response,omitempty"`
	Error    *Error        `json:"error,omitempty"`
}

// HTTPResponse is what a connector reads from an *http.Response.
type HTTPResponse struct {
	StatusCode int         `json:"status_code"`
	Header     http.Header `json:"header,omitempty"`
	Body       []byte      `json:"body,omitempty"`
}

// sentinels is the closed set of errors whose identity crosses the boundary:
// the connector package's own, which hosts test with errors.Is, and the
// standard filesystem and context errors connectors themselves test on what a
// sandbox operation returned (a missing current file, for one, is not a
// failure).
var sentinels = map[string]error{
	"not_exist":                    fs.ErrNotExist,
	"exist":                        fs.ErrExist,
	"permission":                   fs.ErrPermission,
	"canceled":                     context.Canceled,
	"deadline_exceeded":            context.DeadlineExceeded,
	"denied":                       connector.ErrDenied,
	"local_path_refused":           connector.ErrLocalPathRefused,
	"preview_unsupported":          connector.ErrPreviewUnsupported,
	"readback_unsupported":         connector.ErrReadbackUnsupported,
	"readback_not_configured":      connector.ErrReadbackNotConfigured,
	"no_predecessor_installed":     connector.ErrNoPredecessorInstalled,
	"rollback_unsupported":         connector.ErrRollbackUnsupported,
	"rollback_not_configured":      connector.ErrRollbackNotConfigured,
	"takedown_unsupported":         connector.ErrTakedownUnsupported,
	"takedown_object_bound":        connector.ErrTakedownObjectBound,
	"takedown_not_installed":       connector.ErrTakedownNotInstalled,
	"appliance_key_unsupported":    connector.ErrApplianceKeyUnsupported,
	"appliance_key_already_placed": connector.ErrApplianceKeyAlreadyInstalled,
}

// Encode describes err for the other side: nil for nil.
func Encode(err error) *Error {
	if err == nil {
		return nil
	}
	out := &Error{Message: err.Error()}
	for name, sentinel := range sentinels {
		if errors.Is(err, sentinel) {
			out.Is = append(out.Is, name)
		}
	}
	sort.Strings(out.Is)
	return out
}

// Decode rebuilds an error from the other side. The result reads as the same
// text and matches the same sentinels under errors.Is; unknown names are
// ignored rather than trusted.
func (e *Error) Decode() error {
	if e == nil {
		return nil
	}
	var is []error
	for _, name := range e.Is {
		if sentinel, ok := sentinels[name]; ok {
			is = append(is, sentinel)
		}
	}
	return &crossedError{message: e.Message, is: is}
}

type crossedError struct {
	message string
	is      []error
}

func (e *crossedError) Error() string { return e.message }

func (e *crossedError) Is(target error) bool {
	for _, sentinel := range e.is {
		if sentinel == target {
			return true
		}
	}
	return false
}
