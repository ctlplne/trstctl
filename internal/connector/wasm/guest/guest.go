// SPDX-License-Identifier: BUSL-1.1

// Package guest is the connector side of the WASM sandbox: it builds the
// requested first-party connector from the Call's configuration, exactly as the
// host would through native.Build, and runs one operation on it with a Sandbox
// whose every method is a request to the host. The connector code itself has no
// other way out of the module. The module's entry points (package module) wire
// Transport to the host imports; tests wire it to an in-process host.
package guest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/native"
	"trstctl.com/trstctl/internal/connector/wasm/abi"
)

// Transport performs one sandbox operation on the host.
type Transport func(abi.SandboxOp) abi.SandboxResult

// Run executes one encoded abi.Call and returns its Result. It never panics
// across the boundary: a malformed call or a connector failure is an error in
// the Result.
func Run(raw []byte, transport Transport) (result abi.Result) {
	defer func() {
		if r := recover(); r != nil {
			result = abi.Result{Error: &abi.Error{Message: fmt.Sprintf("connector module: operation panicked: %v", r)}}
		}
	}()
	var call abi.Call
	if err := json.Unmarshal(raw, &call); err != nil {
		return failed(fmt.Errorf("connector module: malformed call: %w", err))
	}
	if call.Version != abi.Version {
		return failed(fmt.Errorf("connector module: call version %d is not %d", call.Version, abi.Version))
	}
	credentials := call.Credentials
	built, destroy, err := native.Build(call.Family, call.Config, func(ref, _ string) ([]byte, error) {
		value, ok := credentials[ref]
		if !ok {
			return nil, fmt.Errorf("credential %q was not provided to the sandbox", ref)
		}
		return value, nil
	})
	if err != nil {
		return failed(err)
	}
	defer func() {
		for _, d := range destroy {
			d.Destroy()
		}
		if closer, ok := built.(interface{ Close() }); ok {
			closer.Close()
		}
	}()
	return dispatch(context.Background(), built, &sandbox{transport: transport}, call)
}

func failed(err error) abi.Result { return abi.Result{Error: abi.Encode(err)} }

func dispatch(ctx context.Context, c connector.Connector, sb connector.Sandbox, call abi.Call) abi.Result {
	unsupported := func() abi.Result {
		return failed(fmt.Errorf("connector module: %s does not support %s", call.Family, call.Op))
	}
	switch call.Op {
	case abi.OpDeploy:
		if call.Deployment == nil {
			return failed(fmt.Errorf("connector module: deploy needs a deployment"))
		}
		return failed(c.Deploy(ctx, sb, *call.Deployment))
	case abi.OpReadback:
		r, ok := c.(connector.Readbacker)
		if !ok {
			return unsupported()
		}
		installed, err := r.Readback(ctx, sb, call.TargetName)
		if err != nil {
			return failed(err)
		}
		return abi.Result{Installed: &installed}
	case abi.OpPreview:
		p, ok := c.(connector.Previewer)
		if !ok {
			return unsupported()
		}
		preview, err := p.Preview(ctx, sb, call.TargetName)
		if err != nil {
			return failed(err)
		}
		return abi.Result{Preview: &preview}
	case abi.OpRollback, abi.OpRollbackLegacy:
		if call.Rollback == nil {
			return failed(fmt.Errorf("connector module: rollback needs a rollback"))
		}
		if call.Op == abi.OpRollbackLegacy {
			if r, ok := c.(connector.LegacyRollbacker); ok {
				return failed(r.RollbackLegacy(ctx, sb, *call.Rollback))
			}
			return unsupported()
		}
		if r, ok := c.(connector.Rollbacker); ok {
			return failed(r.Rollback(ctx, sb, *call.Rollback))
		}
		return unsupported()
	case abi.OpTakedown:
		t, ok := c.(connector.Takedowner)
		if !ok || call.Takedown == nil {
			return unsupported()
		}
		return failed(t.Takedown(ctx, sb, *call.Takedown))
	case abi.OpReadTLSPosture, abi.OpApplyTLSPosture:
		p, ok := c.(connector.TLSPostureConnector)
		if !ok {
			return unsupported()
		}
		if call.Op == abi.OpApplyTLSPosture {
			if call.Posture == nil {
				return failed(fmt.Errorf("connector module: apply needs a posture"))
			}
			return failed(p.ApplyTLSPosture(ctx, sb, call.TargetName, *call.Posture))
		}
		posture, err := p.ReadTLSPosture(ctx, sb, call.TargetName)
		if err != nil {
			return failed(err)
		}
		return abi.Result{Posture: &posture}
	case abi.OpGenerateApplianceKey, abi.OpInstallWithApplianceKey:
		g, ok := c.(connector.ApplianceKeyGenerator)
		if !ok {
			return unsupported()
		}
		if call.Op == abi.OpInstallWithApplianceKey {
			if call.Deployment == nil || call.ApplianceKey == nil {
				return failed(fmt.Errorf("connector module: install needs a deployment and a key"))
			}
			return failed(g.InstallWithApplianceKey(ctx, sb, *call.Deployment, *call.ApplianceKey))
		}
		if call.ApplianceKeyRequest == nil {
			return failed(fmt.Errorf("connector module: key generation needs a request"))
		}
		key, err := g.GenerateApplianceKey(ctx, sb, *call.ApplianceKeyRequest)
		if err != nil {
			return failed(err)
		}
		return abi.Result{ApplianceKey: &key}
	}
	return failed(fmt.Errorf("connector module: unknown operation %q", call.Op))
}

// sandbox is the connector's whole world inside the module: each method asks
// the host, which applies the connector's grant and performs the operation.
type sandbox struct{ transport Transport }

func (s *sandbox) do(op abi.SandboxOp) (abi.SandboxResult, error) {
	res := s.transport(op)
	if res.Error != nil {
		return res, res.Error.Decode()
	}
	return res, nil
}

func (s *sandbox) Send(target string, payload []byte) error {
	_, err := s.do(abi.SandboxOp{Op: abi.SandboxSend, Target: target, Payload: payload})
	return err
}

func (s *sandbox) ReadFile(path string) ([]byte, error) {
	res, err := s.do(abi.SandboxOp{Op: abi.SandboxReadFile, Path: path})
	if err != nil {
		return nil, err
	}
	return res.Data, nil
}

func (s *sandbox) WriteFile(path string, data []byte) error {
	_, err := s.do(abi.SandboxOp{Op: abi.SandboxWriteFile, Path: path, Data: data})
	return err
}

func (s *sandbox) Exec(name string, args ...string) error {
	_, err := s.do(abi.SandboxOp{Op: abi.SandboxExec, Name: name, Args: args})
	return err
}

// Request sends the connector's request to the host and rebuilds the response
// it read. The body is read here, so the connector can read and close it as it
// would any response.
func (s *sandbox) Request(req *http.Request) (*http.Response, error) {
	var body []byte
	hasBody := req.Body != nil && req.Body != http.NoBody
	if hasBody {
		var err error
		body, err = io.ReadAll(io.LimitReader(req.Body, abi.MaxBodyBytes+1))
		_ = req.Body.Close()
		if err != nil {
			return nil, err
		}
		if len(body) > abi.MaxBodyBytes {
			return nil, fmt.Errorf("connector module: request body exceeds %d bytes", abi.MaxBodyBytes)
		}
	}
	res, err := s.do(abi.SandboxOp{Op: abi.SandboxHTTP, Request: &abi.HTTPRequest{
		Method: req.Method, URL: req.URL.String(), Header: req.Header.Clone(), HasBody: hasBody, Body: body,
	}})
	if err != nil {
		return nil, err
	}
	if res.Response == nil {
		return nil, fmt.Errorf("connector module: the host returned no response")
	}
	return &http.Response{
		Status:        http.StatusText(res.Response.StatusCode),
		StatusCode:    res.Response.StatusCode,
		Header:        res.Response.Header,
		Body:          io.NopCloser(bytes.NewReader(res.Response.Body)),
		ContentLength: int64(len(res.Response.Body)),
		Request:       req,
		Proto:         "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
	}, nil
}
