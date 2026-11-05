// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// A259: browser sessions. A session opened with "browser": true leaves its
// ticket with the control plane; its opener then works in it from the
// console through terminals the control plane opens through the gateway.

// PAMTerminalRequest opens a terminal: its size, and for a Kubernetes
// session the pod (and optionally the container and command, default sh) to
// exec into.
type PAMTerminalRequest struct {
	Cols      int      `json:"cols"`
	Rows      int      `json:"rows"`
	Namespace string   `json:"namespace,omitempty"`
	Pod       string   `json:"pod,omitempty"`
	Container string   `json:"container,omitempty"`
	Command   []string `json:"command,omitempty"`
}

// PAMTerminal is a shell on a browser session.
type PAMTerminal struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	Cols      int    `json:"cols"`
	Rows      int    `json:"rows"`
}

// PAMTerminalOutput is a terminal's output from an offset: Next is the offset
// to read from next; Truncated says output before Data was no longer kept;
// Closed says the shell ended and nothing more will come.
type PAMTerminalOutput struct {
	Data       []byte `json:"data"`
	Next       int64  `json:"next"`
	Truncated  bool   `json:"truncated,omitempty"`
	Closed     bool   `json:"closed,omitempty"`
	ExitStatus *int   `json:"exit_status,omitempty"`
}

// PAMQueryResult is one SQL text's last result on a database console (part
// 2): its columns and rows (a NULL cell is null), bounded; or the server's
// error, which is a result, not a failure of the call.
type PAMQueryResult struct {
	Columns    []string       `json:"columns"`
	Rows       [][]*string    `json:"rows"`
	CommandTag string         `json:"command_tag,omitempty"`
	Truncated  bool           `json:"truncated,omitempty"`
	Error      *PAMQueryError `json:"error,omitempty"`
}

// PAMQueryError is the database's own refusal of a statement.
type PAMQueryError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// PAMBrowserBridge serves browser sessions; the served broker implements it.
type PAMBrowserBridge interface {
	HoldBrowserTicket(tenantID, sessionID, opener string, delivery PAMGatewayDelivery, ticket []byte, expires time.Time) error
	OpenPAMTerminal(ctx context.Context, tenantID, sessionID, principal string, req PAMTerminalRequest) (PAMTerminal, error)
	ReadPAMTerminal(ctx context.Context, tenantID, sessionID, terminalID, principal string, from int64, wait time.Duration) (PAMTerminalOutput, error)
	WritePAMTerminal(ctx context.Context, tenantID, sessionID, terminalID, principal string, data []byte) error
	ResizePAMTerminal(ctx context.Context, tenantID, sessionID, terminalID, principal string, cols, rows int) error
	ClosePAMTerminal(ctx context.Context, tenantID, sessionID, terminalID, principal string) error
	RunPAMQuery(ctx context.Context, tenantID, sessionID, principal, sql string) (PAMQueryResult, error)
}

func (a *API) pamBrowserRoutes() []route {
	session := []param{pathUUID("id")}
	terminal := []param{pathUUID("id"), pathUUID("terminal_id")}
	return []route{
		{method: "POST", path: "/api/v1/access/sessions/{id}/terminals", opID: "openPAMTerminal", summary: "Open a terminal on your SSH or Kubernetes session opened for the browser (a shell, or an exec in a pod); the control plane holds its ticket and the gateway signs in", handler: a.openPAMTerminal, pathParams: session, reqSchema: "PAMTerminalRequest", resSchema: "PAMTerminal", successCode: "201", mutation: true, perm: authz.AccessSessionsOpen},
		{method: "GET", path: "/api/v1/access/sessions/{id}/terminals/{terminal_id}/output", opID: "readPAMTerminalOutput", summary: "Read a terminal's output from an offset; wait long-polls for output still to come", handler: a.readPAMTerminal, pathParams: terminal, query: []param{{name: "from", typ: "integer", desc: "offset to read from (the previous read's next)"}, {name: "wait", typ: "integer", desc: "seconds to wait for output, at most 25"}}, resSchema: "PAMTerminalOutput", successCode: "200", sensitiveResponse: true, perm: authz.AccessSessionsOpen},
		{method: "POST", path: "/api/v1/access/sessions/{id}/terminals/{terminal_id}/input", opID: "writePAMTerminalInput", summary: "Type into a terminal; a retried request with the same Idempotency-Key types nothing twice", handler: a.writePAMTerminal, pathParams: terminal, reqSchema: "PAMTerminalInput", resSchema: "PAMTerminal", successCode: "200", mutation: true, perm: authz.AccessSessionsOpen},
		{method: "POST", path: "/api/v1/access/sessions/{id}/terminals/{terminal_id}/resize", opID: "resizePAMTerminal", summary: "Change a terminal's size", handler: a.resizePAMTerminal, pathParams: terminal, reqSchema: "PAMTerminalRequest", resSchema: "PAMTerminal", successCode: "200", mutation: true, perm: authz.AccessSessionsOpen},
		{method: "POST", path: "/api/v1/access/sessions/{id}/queries", opID: "runPAMQuery", summary: "Run SQL on your PostgreSQL session opened for the browser; the gateway signs in, records and masks, and the reply holds the last result's rows", handler: a.runPAMQuery, pathParams: session, reqSchema: "PAMQueryRequest", resSchema: "PAMQueryResult", successCode: "200", mutation: true, sensitiveResponse: true, perm: authz.AccessSessionsOpen},
		{method: "DELETE", path: "/api/v1/access/sessions/{id}/terminals/{terminal_id}", opID: "closePAMTerminal", summary: "End a terminal; the session stays open", handler: a.closePAMTerminal, pathParams: terminal, resSchema: "PAMTerminal", successCode: "200", mutation: true, perm: authz.AccessSessionsOpen},
	}
}

func (a *API) browserBridge() (PAMBrowserBridge, error) {
	bridge, ok := a.pam.(PAMBrowserBridge)
	if a.pam == nil || !ok {
		return nil, ErrPAMUnavailable
	}
	return bridge, nil
}

// holdBrowserTicket hands an opened session's ticket to the control plane
// and takes it out of the reply.
func (a *API) holdBrowserTicket(tenantID, opener string, session *PAMSession) error {
	bridge, err := a.browserBridge()
	if err != nil {
		return err
	}
	if session.Gateway == nil || len(session.Gateway.Ticket) == 0 {
		return errStatus(http.StatusUnprocessableEntity, "only a session through a gateway opens in the browser")
	}
	err = bridge.HoldBrowserTicket(tenantID, session.ID, opener, *session.Gateway, []byte(session.Gateway.Ticket), session.ExpiresAt)
	secret.Wipe([]byte(session.Gateway.Ticket))
	session.Gateway.Ticket = nil
	return err
}

//trstctl:mutation
func (a *API) openPAMTerminal(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		bridge, err := a.browserBridge()
		if err != nil {
			return 0, nil, err
		}
		var body PAMTerminalRequest
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		terminal, err := bridge.OpenPAMTerminal(ctx, tenantID, r.PathValue("id"), principalSubject(ctx), body)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, terminal, nil
	})
}

func (a *API) readPAMTerminal(w http.ResponseWriter, r *http.Request) {
	bridge, err := a.browserBridge()
	if err != nil {
		a.writePAMError(w, err)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	query := r.URL.Query()
	from, err := strconv.ParseInt(strings.TrimSpace(query.Get("from")), 10, 64)
	if query.Get("from") == "" {
		from, err = 0, nil
	}
	if err != nil || from < 0 {
		a.writeError(w, errStatus(http.StatusBadRequest, "from must be a non-negative offset"))
		return
	}
	wait := 0
	if raw := query.Get("wait"); raw != "" {
		if wait, err = strconv.Atoi(raw); err != nil || wait < 0 || wait > 25 {
			a.writeError(w, errStatus(http.StatusBadRequest, "wait must be 0-25 seconds"))
			return
		}
	}
	out, err := bridge.ReadPAMTerminal(r.Context(), tenantID, r.PathValue("id"), r.PathValue("terminal_id"), principalSubject(r.Context()),
		from, time.Duration(wait)*time.Second)
	if err != nil {
		if !a.writePAMError(w, err) {
			a.writeError(w, err)
		}
		return
	}
	a.writeJSON(w, http.StatusOK, out)
}

//trstctl:mutation
func (a *API) writePAMTerminal(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		bridge, err := a.browserBridge()
		if err != nil {
			return 0, nil, err
		}
		var body struct {
			Data string `json:"data"`
		}
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		data, err := base64.StdEncoding.DecodeString(body.Data)
		if err != nil {
			return 0, nil, errStatus(http.StatusBadRequest, "data must be standard base64")
		}
		defer secret.Wipe(data)
		if err := bridge.WritePAMTerminal(ctx, tenantID, r.PathValue("id"), r.PathValue("terminal_id"), principalSubject(ctx), data); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, PAMTerminal{ID: r.PathValue("terminal_id"), SessionID: r.PathValue("id")}, nil
	})
}

//trstctl:mutation
func (a *API) resizePAMTerminal(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		bridge, err := a.browserBridge()
		if err != nil {
			return 0, nil, err
		}
		var body struct {
			Cols int `json:"cols"`
			Rows int `json:"rows"`
		}
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if err := bridge.ResizePAMTerminal(ctx, tenantID, r.PathValue("id"), r.PathValue("terminal_id"), principalSubject(ctx), body.Cols, body.Rows); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, PAMTerminal{ID: r.PathValue("terminal_id"), SessionID: r.PathValue("id"), Cols: body.Cols, Rows: body.Rows}, nil
	})
}

//trstctl:mutation
func (a *API) closePAMTerminal(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		bridge, err := a.browserBridge()
		if err != nil {
			return 0, nil, err
		}
		err = bridge.ClosePAMTerminal(ctx, tenantID, r.PathValue("id"), r.PathValue("terminal_id"), principalSubject(ctx))
		if err != nil && !errors.Is(err, ErrPAMTerminal) {
			return 0, nil, err
		}
		return http.StatusOK, PAMTerminal{ID: r.PathValue("terminal_id"), SessionID: r.PathValue("id")}, nil
	})
}

//trstctl:mutation
func (a *API) runPAMQuery(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		bridge, err := a.browserBridge()
		if err != nil {
			return 0, nil, err
		}
		var body struct {
			SQL string `json:"sql"`
		}
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		result, err := bridge.RunPAMQuery(ctx, tenantID, r.PathValue("id"), principalSubject(ctx), body.SQL)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, result, nil
	})
}
