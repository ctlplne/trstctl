// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/store"
)

// A259 part 2: the database console. For a PostgreSQL session opened for the
// browser, the control plane keeps one connection through the session's
// gateway for its opener and runs one statement at a time on it; the gateway
// signs in as the session's login, records each statement with its bounded
// results and masks, as for a stock client. The browser gets the result rows,
// never a credential. MySQL, MongoDB and Redis sessions have consoles of the
// same kind (A259-L5, pam_browser_console.go).

const (
	pamConsoleMaxRows = 1000
	pamConsoleMaxCell = 4 << 10
	pamConsoleMaxSQL  = 64 << 10
	pamConsoleTimeout = 60 * time.Second
)

// pamConsole is one session's console connection.
type pamConsole struct {
	mu     sync.Mutex
	client pamConsoleClient
}

// pamConsoleSQL are the session types whose console runs SQL; a MongoDB or
// Redis console runs a command.
var pamConsoleSQL = map[string]bool{pamTargetPostgres: true, pamTargetMySQL: true, pamTargetMongo: false, pamTargetRedis: false}

// RunPAMQuery runs one SQL text or command on a PostgreSQL, MySQL, MongoDB or
// Redis browser session for its opener and returns the last result's columns
// and rows, bounded.
func (s *pamService) RunPAMQuery(ctx context.Context, tenantID, sessionID, principal string, req api.PAMQueryRequest) (api.PAMQueryResult, error) {
	sql, command := strings.TrimSpace(req.SQL), strings.TrimSpace(req.Command)
	text := sql + command
	if (sql == "") == (command == "") || len(text) > pamConsoleMaxSQL {
		return api.PAMQueryResult{}, fmt.Errorf("%w: SQL or a command of 1-%d bytes is required", api.ErrPAMInvalid, pamConsoleMaxSQL)
	}
	rec, err := s.store.GetPAMSession(ctx, tenantID, sessionID)
	if err != nil {
		return api.PAMQueryResult{}, err
	}
	runsSQL, served := pamConsoleSQL[rec.TargetType]
	if !served || rec.Delivery != "gateway" || rec.Status != api.PAMSessionStatusActive || !s.clock().Before(rec.ExpiresAt) {
		return api.PAMQueryResult{}, fmt.Errorf("%w: the console needs an active PostgreSQL, MySQL, MongoDB or Redis session through a gateway", api.ErrPAMRejected)
	}
	if runsSQL != (sql != "") {
		return api.PAMQueryResult{}, fmt.Errorf("%w: a PostgreSQL or MySQL console runs sql; a MongoDB or Redis console runs a command", api.ErrPAMInvalid)
	}
	console, err := s.console(ctx, tenantID, sessionID, principal, rec)
	if err != nil {
		return api.PAMQueryResult{}, err
	}
	console.mu.Lock()
	defer console.mu.Unlock()
	qctx, cancel := context.WithTimeout(ctx, pamConsoleTimeout)
	defer cancel()
	result, err := console.client.run(qctx, text)
	if errors.Is(err, errPAMConsoleInput) {
		return api.PAMQueryResult{}, fmt.Errorf("%w: %s", api.ErrPAMInvalid, strings.TrimPrefix(err.Error(), errPAMConsoleInput.Error()+": "))
	}
	if err != nil {
		s.dropConsole(tenantID, sessionID)
		return api.PAMQueryResult{}, fmt.Errorf("%w: the session's connection ended: %v", api.ErrPAMTerminal, err)
	}
	return result, nil
}

// pgConsole runs SQL on a PostgreSQL session's console connection.
type pgConsole struct{ conn *pgconn.PgConn }

func (c *pgConsole) close() { _ = c.conn.Close(context.Background()) }

func (c *pgConsole) run(ctx context.Context, sql string) (api.PAMQueryResult, error) {
	results, err := c.conn.Exec(ctx, sql).ReadAll()
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			return api.PAMQueryResult{Error: &api.PAMQueryError{Code: pgErr.Code, Message: pgErr.Message}}, nil
		}
		return api.PAMQueryResult{}, err
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
			var cut bool
			cells[j], cut = pamConsoleCell(value)
			out.Truncated = out.Truncated || cut
		}
		out.Rows = append(out.Rows, cells)
	}
	return out, nil
}

// console is the session's console connection for its opener, opened through
// the gateway on first use with the client the session's type speaks.
func (s *pamService) console(ctx context.Context, tenantID, sessionID, principal string, rec store.PAMSession) (*pamConsole, error) {
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
	// The connection is already open and admitted: the gateway answers as
	// the session's database and signs in upstream as the session's account.
	var client pamConsoleClient
	switch rec.TargetType {
	case pamTargetPostgres:
		config, err := pgconn.ParseConfig("postgres://browser@trstctl-gateway/postgres?sslmode=disable&application_name=trstctl-console")
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
		config.LookupFunc = func(context.Context, string) ([]string, error) { return []string{"trstctl-gateway"}, nil }
		config.DialFunc = func(context.Context, string, string) (net.Conn, error) { return raw, nil }
		conn, err := pgconn.ConnectConfig(dctx, config)
		if err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("%w: the session's gateway did not sign in: %v", api.ErrPAMRejected, err)
		}
		client = &pgConsole{conn: conn}
	case pamTargetMySQL:
		mysqlClient, err := newMySQLConsole(dctx, raw)
		if err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("%w: the session's gateway did not sign in: %v", api.ErrPAMRejected, err)
		}
		client = mysqlClient
	case pamTargetRedis:
		client = &redisConsole{conn: raw, r: bufio.NewReader(raw)}
	case pamTargetMongo:
		client = &mongoConsole{conn: raw, r: bufio.NewReader(raw), database: s.consoleDatabase(ctx, tenantID, rec)}
	default:
		_ = raw.Close()
		return nil, fmt.Errorf("%w: a %s session has no console", api.ErrPAMRejected, rec.TargetType)
	}
	console := &pamConsole{client: client}
	s.browser.mu.Lock()
	if other := s.browser.consoles[key]; other != nil {
		s.browser.mu.Unlock()
		client.close()
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
		console.client.close()
	}
}

// consoleDatabase is the database a MongoDB session's provider grants on: a
// console command runs there unless it names $db.
func (s *pamService) consoleDatabase(ctx context.Context, tenantID string, rec store.PAMSession) string {
	target, err := s.databaseTarget(ctx, tenantID, rec.TargetType, rec.TargetID)
	if err != nil {
		return "admin"
	}
	for _, provider := range s.providers.ForTenant(tenantID) {
		if provider == nil || provider.Name() != target.cfg.ProviderID {
			continue
		}
		if named, ok := provider.(interface{ DynamicSecretDatabase() string }); ok && named.DynamicSecretDatabase() != "" {
			return named.DynamicSecretDatabase()
		}
	}
	return "admin"
}
