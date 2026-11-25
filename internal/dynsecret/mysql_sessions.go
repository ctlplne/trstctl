// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// mysqlSessionInspector is the narrow seam for a test or alternate executor.
// The shipped *sql.DB path below proves the admin can see every connection,
// then reads the real MySQL process list. An executor unable to provide that
// proof must fail revocation, never report an empty process list.
type mysqlSessionInspector interface {
	mysqlSessionIDs(context.Context, string) ([]int64, error)
}

func mysqlLeaseSessionIDs(ctx context.Context, exec SQLExecutor, user string) ([]int64, error) {
	if inspector, ok := exec.(mysqlSessionInspector); ok {
		return inspector.mysqlSessionIDs(ctx, user)
	}
	db, ok := exec.(*sql.DB)
	if !ok {
		return nil, errors.New("session inspection is unavailable")
	}
	if err := mysqlRequireProcessPrivilege(ctx, db); err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT ID FROM INFORMATION_SCHEMA.PROCESSLIST WHERE USER = ?`, user)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if id <= 0 || len(ids) >= 4096 {
			return nil, errors.New("invalid or excessive process-list results")
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	slices.Sort(ids)
	return ids, nil
}

func mysqlRequireProcessPrivilege(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `SHOW GRANTS FOR CURRENT_USER()`)
	if err != nil {
		return fmt.Errorf("read administrator grants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	allowed := false
	for rows.Next() {
		var grant string
		if err := rows.Scan(&grant); err != nil {
			return err
		}
		grant = strings.ToUpper(grant)
		permissions, _, onGlobal := strings.Cut(strings.TrimPrefix(grant, "GRANT "), " ON *.* TO ")
		if !onGlobal {
			continue
		}
		if permissions == "ALL PRIVILEGES" || slices.Contains(strings.Split(permissions, ", "), "PROCESS") {
			allowed = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !allowed {
		return errors.New("administrator needs a direct global PROCESS grant to inspect every lease session")
	}
	return nil
}
