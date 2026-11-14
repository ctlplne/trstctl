// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Q6-L6: refused sign-ins by a decoy login, read where PostgreSQL writes them.
// PostgreSQL keeps no statistic for a refused authentication, so the decoy
// database's session counter never sees a wrong password. With jsonlog in
// log_destination and the logging collector on, the server's structured log
// records each refusal — SQLSTATE 28P01 (invalid_password) or 28000
// (invalid_authorization_specification) — with the role it was for. The
// provider's admin connection reads the current log through
// pg_current_logfile and pg_read_file (a superuser, or a member of pg_monitor
// with EXECUTE on pg_read_file), a bounded chunk at a time from where the
// last read stopped.

// DecoyLogCursor is where a reader of the server's jsonlog stopped.
type DecoyLogCursor struct {
	File   string
	Offset int64
}

// DecoyFailedLogin is one refused sign-in by a watched role.
type DecoyFailedLogin struct {
	Role, Database, RemoteHost, StateCode string
	At                                    time.Time
}

// decoyAuthLogChunk bounds one read of the server log (AN-7).
const decoyAuthLogChunk = 1 << 20

// ErrDecoyAuthLogUnavailable is a server that writes no jsonlog.
var ErrDecoyAuthLogUnavailable = errors.New("dynsecret postgres: the server writes no jsonlog (set log_destination to include jsonlog and logging_collector to on)")

// DecoyFailedLogins reads the server's jsonlog from cursor and returns the
// refused sign-ins by any of roles and where the read stopped. A log the
// server rotated away from is read to its end before the new one; a partial
// last line waits for the next read.
func (b *PostgresBackend) DecoyFailedLogins(ctx context.Context, cursor DecoyLogCursor, roles map[string]bool) ([]DecoyFailedLogin, DecoyLogCursor, error) {
	conn, err := connectPostgresAdmin(ctx, b.dsn.Bytes())
	if err != nil {
		return nil, cursor, err
	}
	defer func() { _ = conn.Close(ctx) }()
	var current *string
	if err := conn.QueryRow(ctx, `SELECT pg_current_logfile('jsonlog')`).Scan(&current); err != nil {
		return nil, cursor, fmt.Errorf("dynsecret postgres: read the current log file: %w", err)
	}
	if current == nil || *current == "" {
		return nil, cursor, ErrDecoyAuthLogUnavailable
	}
	var found []DecoyFailedLogin
	if cursor.File != "" && cursor.File != *current {
		more, next, done, err := readDecoyAuthLog(ctx, conn, cursor, roles)
		if err != nil {
			return nil, cursor, err
		}
		found = append(found, more...)
		if !done {
			return found, next, nil
		}
		cursor = DecoyLogCursor{}
	}
	if cursor.File != *current {
		cursor = DecoyLogCursor{File: *current}
	}
	more, next, _, err := readDecoyAuthLog(ctx, conn, cursor, roles)
	if err != nil {
		return nil, cursor, err
	}
	return append(found, more...), next, nil
}

// readDecoyAuthLog reads one bounded chunk of a log file from the cursor:
// the refusals on its complete lines, the cursor after them, and whether the
// read reached the end of the file.
func readDecoyAuthLog(ctx context.Context, conn *pgx.Conn, cursor DecoyLogCursor, roles map[string]bool) ([]DecoyFailedLogin, DecoyLogCursor, bool, error) {
	var chunk *string
	if err := conn.QueryRow(ctx, `SELECT pg_read_file($1, $2, $3, true)`, cursor.File, cursor.Offset, int64(decoyAuthLogChunk)).Scan(&chunk); err != nil {
		return nil, cursor, false, fmt.Errorf("dynsecret postgres: read the server log: %w", err)
	}
	if chunk == nil {
		// The file is gone (removed by log rotation): nothing more to read.
		return nil, cursor, true, nil
	}
	data := *chunk
	end := strings.LastIndexByte(data, '\n')
	if end < 0 {
		if len(data) >= decoyAuthLogChunk {
			// One line longer than the bound: skip it rather than stall.
			cursor.Offset += int64(len(data))
			return nil, cursor, false, nil
		}
		return nil, cursor, true, nil
	}
	found := parseDecoyAuthLog(data[:end], roles)
	cursor.Offset += int64(end + 1)
	return found, cursor, len(data) < decoyAuthLogChunk, nil
}

// parseDecoyAuthLog reads the refusals by roles from complete jsonlog lines.
// A line that is not a JSON log record is skipped.
func parseDecoyAuthLog(lines string, roles map[string]bool) []DecoyFailedLogin {
	var found []DecoyFailedLogin
	for _, line := range strings.Split(lines, "\n") {
		if !strings.Contains(line, `"state_code":"28`) {
			continue
		}
		var rec struct {
			Timestamp  string `json:"timestamp"`
			User       string `json:"user"`
			Database   string `json:"dbname"`
			RemoteHost string `json:"remote_host"`
			StateCode  string `json:"state_code"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil || (rec.StateCode != "28P01" && rec.StateCode != "28000") || !roles[rec.User] {
			continue
		}
		at, err := time.Parse("2006-01-02 15:04:05.000 MST", rec.Timestamp)
		if err != nil {
			at = time.Now().UTC()
		}
		found = append(found, DecoyFailedLogin{Role: rec.User, Database: rec.Database, RemoteHost: rec.RemoteHost, StateCode: rec.StateCode, At: at.UTC()})
	}
	return found
}
