// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"testing"
)

type cr260MySQLExecutor struct {
	dropped    bool
	sessions   map[int64]bool
	refuseKill bool
	killCount  map[int64]int
	endAfter   int
}

func (e *cr260MySQLExecutor) ExecContext(_ context.Context, query string, _ ...any) (sql.Result, error) {
	switch {
	case strings.HasPrefix(query, "DROP USER IF EXISTS "):
		e.dropped = true
	case strings.HasPrefix(query, "KILL CONNECTION "):
		id, err := strconv.ParseInt(strings.TrimPrefix(query, "KILL CONNECTION "), 10, 64)
		if err != nil {
			return nil, err
		}
		if e.refuseKill {
			return nil, errors.New("kill refused")
		}
		if e.killCount == nil {
			e.killCount = map[int64]int{}
		}
		e.killCount[id]++
		if e.killCount[id] >= e.endAfter {
			delete(e.sessions, id)
		}
	}
	return nil, nil
}

func (e *cr260MySQLExecutor) mysqlSessionIDs(_ context.Context, _ string) ([]int64, error) {
	if !e.dropped {
		return nil, errors.New("sessions inspected before account drop")
	}
	var ids []int64
	for id := range e.sessions {
		ids = append(ids, id)
	}
	return ids, nil
}

func TestCR260MySQLRevokeEndsExistingSessionsBeforeSuccess(t *testing.T) {
	exec := &cr260MySQLExecutor{sessions: map[int64]bool{41: true, 42: true}}
	b, err := NewMySQLBackend(exec, MySQLConfig{Database: "app", Addr: "mysql.internal:3306", AccountHost: "%", AllowWildcardAccountHost: true, UsernamePrefix: "trstctl"})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Revoke(context.Background(), "trstctl_r_0123456789"); err != nil {
		t.Fatal(err)
	}
	if len(exec.sessions) != 0 {
		t.Fatalf("revoke reported success with %d live lease sessions", len(exec.sessions))
	}
}

func TestCR260MySQLRevokeFailsWhileSessionSurvives(t *testing.T) {
	exec := &cr260MySQLExecutor{sessions: map[int64]bool{41: true}, refuseKill: true}
	b, err := NewMySQLBackend(exec, MySQLConfig{Database: "app", Addr: "mysql.internal:3306", AccountHost: "%", AllowWildcardAccountHost: true, UsernamePrefix: "trstctl"})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Revoke(context.Background(), "trstctl_r_0123456789"); err == nil {
		t.Fatal("revoke succeeded after KILL was refused")
	}
}

func TestCR260MySQLRevokeChecksAfterLastKill(t *testing.T) {
	exec := &cr260MySQLExecutor{sessions: map[int64]bool{41: true}, endAfter: 4}
	b, err := NewMySQLBackend(exec, MySQLConfig{Database: "app", Addr: "mysql.internal:3306", AccountHost: "%", AllowWildcardAccountHost: true, UsernamePrefix: "trstctl"})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Revoke(context.Background(), "trstctl_r_0123456789"); err != nil {
		t.Fatalf("fourth KILL ended the session but revoke did not re-list: %v", err)
	}
}

func TestCR260MySQLRevokeRejectsAStillLiveSessionAfterAllKills(t *testing.T) {
	exec := &cr260MySQLExecutor{sessions: map[int64]bool{41: true}, endAfter: 5}
	b, err := NewMySQLBackend(exec, MySQLConfig{Database: "app", Addr: "mysql.internal:3306", AccountHost: "%", AllowWildcardAccountHost: true, UsernamePrefix: "trstctl"})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Revoke(context.Background(), "trstctl_r_0123456789"); err == nil {
		t.Fatal("revoke succeeded after every KILL was accepted but the session stayed live")
	}
}
