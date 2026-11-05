// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/api"
)

// A259 part 2: the database console. For a PostgreSQL session opened for the
// browser, the control plane keeps one connection through the session's
// gateway for its opener and runs one statement at a time on it; the gateway
// signs in as the session's login, records each statement with its bounded
// results and masks, as for a stock client. The browser gets the result rows,
// never a credential.

const (
	pamConsoleMaxRows = 1000
	pamConsoleMaxCell = 4 << 10
	pamConsoleMaxSQL  = 64 << 10
	pamConsoleTimeout = 60 * time.Second
)

// pamConsole is one session's console connection.
type pamConsole struct {
	mu   sync.Mutex
	conn *pgconn.PgConn
}

// RunPAMQuery runs one SQL text on a PostgreSQL browser session for its
// opener and returns the last result's columns and rows, bounded.
func (s *pamService) RunPAMQuery(ctx context.Context, tenantID, sessionID, principal, sql string) (api.PAMQueryResult, error) {
	sql = strings.TrimSpace(sql)
	if sql == "" || len(sql) > pamConsoleMaxSQL {
		return api.PAMQueryResult{}, fmt.Errorf("%w: SQL of 1-%d bytes is required", api.ErrPAMInvalid, pamConsoleMaxSQL)
	}
	rec, err := s.store.GetPAMSession(ctx, tenantID, sessionID)
	if err != nil {
		return api.PAMQueryResult{}, err
	}
	if rec.TargetType != pamTargetPostgres || rec.Delivery != "gateway" || rec.Status != api.PAMSessionStatusActive || !s.clock().Before(rec.ExpiresAt) {
		return api.PAMQueryResult{}, fmt.Errorf("%w: the console needs an active PostgreSQL session through a gateway", api.ErrPAMRejected)
	}
	console, err := s.console(ctx, tenantID, sessionID, principal)
	if err != nil {
		return api.PAMQueryResult{}, err
	}
	console.mu.Lock()
	defer console.mu.Unlock()
	qctx, cancel := context.WithTimeout(ctx, pamConsoleTimeout)
	defer cancel()
	results, err := console.conn.Exec(qctx, sql).ReadAll()
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			return api.PAMQueryResult{Error: &api.PAMQueryError{Code: pgErr.Code, Message: pgErr.Message}}, nil
		}
		s.dropConsole(tenantID, sessionID)
		return api.PAMQueryResult{}, fmt.Errorf("%w: the session's connection ended: %v", api.ErrPAMTerminal, err)
	}
	out := api.PAMQueryResult{Columns: []string{}, Rows: [][]*string{}}
	if len(results) == 0 {
		return out, nil
	}
	last := results[len(results)-1]
	out.CommandTag = last.CommandTag.String()
	for _, field := range last.FieldDescriptions {
		out.Columns = append(out.Columns, field.Name)
	}
	for i, row := range last.Rows {
		if i == pamConsoleMaxRows {
			out.Truncated = true
			break
		}
		cells := make([]*string, len(row))
		for j, value := range row {
			if value == nil {
				continue
			}
			cell := string(value)
			if len(cell) > pamConsoleMaxCell {
				cell = strings.ToValidUTF8(cell[:pamConsoleMaxCell], "") + "…"
				out.Truncated = true
			}
			if !utf8.ValidString(cell) {
				cell = strings.ToValidUTF8(cell, "�")
			}
			cells[j] = &cell
		}
		out.Rows = append(out.Rows, cells)
	}
	return out, nil
}

// console is the session's console connection for its opener, opened through
// the gateway on first use.
func (s *pamService) console(ctx context.Context, tenantID, sessionID, principal string) (*pamConsole, error) {
	key := pamBrowserKey{tenantID, sessionID}
	s.browser.mu.Lock()
	held := s.browser.tickets[key]
	existing := s.browser.consoles[key]
	s.browser.mu.Unlock()
	switch {
	case held == nil:
		return nil, fmt.Errorf("%w: the session was not opened for the browser", api.ErrPAMRejected)
	case held.opener != principal:
		return nil, fmt.Errorf("%w: only the person who opened the session can use it in the browser", api.ErrPAMRejected)
	case existing != nil:
		return existing, nil
	}
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	raw, err := s.browser.dial(dctx, held.address, held.caPEM, held.spiffeID)
	if err != nil {
		return nil, fmt.Errorf("%w: the session's gateway: %v", api.ErrPAMRejected, err)
	}
	if _, err := admitAtGateway(raw, sessionID, held.ticket); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("%w: %v", api.ErrPAMRejected, err)
	}
	config, err := pgconn.ParseConfig("postgres://browser@trstctl-gateway/postgres?sslmode=disable&application_name=trstctl-console")
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	// The connection is already open and admitted: the gateway answers as
	// PostgreSQL and signs in upstream as the session's login.
	config.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"trstctl-gateway"}, nil }
	config.DialFunc = func(context.Context, string, string) (net.Conn, error) { return raw, nil }
	conn, err := pgconn.ConnectConfig(dctx, config)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("%w: the session's gateway did not sign in: %v", api.ErrPAMRejected, err)
	}
	console := &pamConsole{conn: conn}
	s.browser.mu.Lock()
	if other := s.browser.consoles[key]; other != nil {
		s.browser.mu.Unlock()
		_ = conn.Close(context.Background())
		return other, nil
	}
	s.browser.consoles[key] = console
	s.browser.mu.Unlock()
	return console, nil
}

func (s *pamService) dropConsole(tenantID, sessionID string) {
	key := pamBrowserKey{tenantID, sessionID}
	s.browser.mu.Lock()
	console := s.browser.consoles[key]
	delete(s.browser.consoles, key)
	s.browser.mu.Unlock()
	if console != nil {
		_ = console.conn.Close(context.Background())
	}
}
