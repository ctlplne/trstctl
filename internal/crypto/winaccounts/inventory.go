// SPDX-License-Identifier: BUSL-1.1
// Package winaccounts reads and binds local Windows SAM account identity.
// It never interprets a domain account as a local rotation target.
package winaccounts

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const MaxInventoryBytes = 1 << 20

var (
	ErrUnsupported    = errors.New("windows local accounts: native member or standalone Windows host required")
	ErrInventory      = errors.New("windows local accounts: native inventory is incomplete or changed")
	ErrInventoryBound = errors.New("windows local accounts: native inventory exceeds its bounded observation budget")
)

// Machine identifies the local SAM. Roles 0–3 are workstation/member/standalone
// roles; roles 4–5 are domain controllers and cannot grant local-SAM authority.
type Machine struct {
	Name string `json:"name"`
	SID  string `json:"sid"`
	Role uint32 `json:"role"`
}

// Account contains public metadata only. It carries no password or password hash.
type Account struct {
	Name             string `json:"name"`
	SID              string `json:"sid"`
	Enabled          bool   `json:"enabled"`
	Locked           bool   `json:"locked"`
	PasswordRequired bool   `json:"password_required"`
}
type Inventory struct {
	Machine         Machine   `json:"machine"`
	Accounts        []Account `json:"accounts"`
	ExternalMembers int       `json:"external_members"`
	GroupMembers    int       `json:"group_members"`
	DeletedMembers  int       `json:"deleted_members"`
}

// Member is a native alias member SID and optional SID_NAME_USE value. Zero
// means SID-only enumeration: User must independently confirm a local user. The native
// driver must finish/drain enumeration even when the callback refuses a record.
type Member struct {
	SID string
	Use uint32
}
type driver interface {
	Machine(context.Context) (Machine, error)
	Administrators(context.Context, func(Member) error) error
	User(context.Context, string) (Account, error)
}
type Adapter struct{ driver driver }

func New() Adapter { return Adapter{driver: newNativeDriver()} }

// Inventory returns a complete read or no account list. Local account lookup is
// permitted only after checking the machine's role and exact SAM SID prefix.
func (a Adapter) Inventory(ctx context.Context) (Inventory, error) {
	var none Inventory
	if err := ctx.Err(); err != nil {
		return none, err
	}
	if a.driver == nil {
		return none, ErrUnsupported
	}
	machine, err := a.driver.Machine(ctx)
	if err != nil {
		return none, err
	}
	if machine.Role > 3 {
		return none, ErrUnsupported
	}
	if !validMachineSID(machine.SID) || machine.Name == "" || len(machine.Name) > 255 || !utf8.ValidString(machine.Name) || strings.ContainsRune(machine.Name, 0) {
		return none, ErrInventory
	}
	result := Inventory{Machine: machine, Accounts: []Account{}}
	seen := map[string]bool{}
	budget := 1024
	err = a.driver.Administrators(ctx, func(member Member) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !validSID(member.SID) || seen[member.SID] {
			return ErrInventory
		}
		budget += len(member.SID) + 16
		if budget > MaxInventoryBytes {
			return ErrInventoryBound
		}
		seen[member.SID] = true
		if member.Use == 2 || member.Use == 4 || member.Use == 5 {
			result.GroupMembers++
			return nil
		}
		if !localSID(machine.SID, member.SID) {
			result.ExternalMembers++
			return nil
		}
		if member.Use == 6 {
			result.DeletedMembers++
			return nil
		}
		if member.Use != 0 && member.Use != 1 {
			return ErrInventory
		}
		account, err := a.driver.User(ctx, member.SID)
		if err != nil {
			return err
		}
		if account.SID != member.SID || !validName(account.Name) {
			return ErrInventory
		}
		encoded, err := json.Marshal(account)
		if err != nil {
			return err
		}
		budget += len(encoded) + 1
		if budget > MaxInventoryBytes {
			return ErrInventoryBound
		}
		result.Accounts = append(result.Accounts, account)
		return nil
	})
	if err != nil {
		return none, err
	}
	after, err := a.driver.Machine(ctx)
	if err != nil {
		return none, err
	}
	if after != machine {
		return none, ErrInventory
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return none, err
	}
	if len(encoded) > MaxInventoryBytes {
		return none, ErrInventoryBound
	}
	sort.Slice(result.Accounts, func(i, j int) bool { return result.Accounts[i].SID < result.Accounts[j].SID })
	return result, nil
}
func canonicalNumber(raw string, bits int) bool {
	if raw == "" || len(raw) > 1 && raw[0] == '0' {
		return false
	}
	n, err := strconv.ParseUint(raw, 10, bits)
	return err == nil && strconv.FormatUint(n, 10) == raw
}
func validSID(sid string) bool {
	if len(sid) > 192 {
		return false
	}
	parts := strings.Split(sid, "-")
	if len(parts) < 4 || len(parts) > 18 || parts[0] != "S" || parts[1] != "1" || !canonicalNumber(parts[2], 48) {
		return false
	}
	for _, part := range parts[3:] {
		if !canonicalNumber(part, 32) {
			return false
		}
	}
	return true
}
func validMachineSID(sid string) bool {
	if !validSID(sid) {
		return false
	}
	parts := strings.Split(sid, "-")
	return len(parts) == 7 && strings.HasPrefix(sid, "S-1-5-21-")
}
func localSID(machine, sid string) bool {
	suffix, ok := strings.CutPrefix(sid, machine+"-")
	return ok && canonicalNumber(suffix, 32) && suffix != "0"
}

// Native names are public UTF-16 metadata. This validator is deliberately not
// the old SSH profile's interpolation validator and is never used to build argv.
func validName(name string) bool {
	if name == "" || len(name) > 80 || !utf8.ValidString(name) || strings.HasSuffix(name, ".") || strings.ContainsAny(name, `"/\[]:;|=,+*?<>`) {
		return false
	}
	units := 0
	for _, r := range name {
		if r < 32 || r == 127 {
			return false
		}
		units += utf16.RuneLen(r)
	}
	return units <= 20
}
