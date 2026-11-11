// SPDX-License-Identifier: BUSL-1.1

package secretrender

import (
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strconv"
)

// A238-L2: a template can give its file to the application's user and group.
// The agent gives the private temporary file away before it renames it over the
// destination, so the file is never seen with another owner. Only root gives a
// file to another user, so a template that names an owner or a group needs the
// agent to run as root; on Windows the file's DACL already names who reads it.

// fileOwnership is the uid and gid a template's file is given; -1 leaves one
// as it is.
type fileOwnership struct {
	uid, gid int
}

// effectiveUID is the agent's effective user ID; a test can stand in for root
// to check name resolution without giving anything away.
var effectiveUID = os.Geteuid

// ownership resolves the template's owner and group. Neither set: the file
// stays the agent's (nil).
func (t Template) ownership() (*fileOwnership, error) {
	if t.Owner == "" && t.Group == "" {
		return nil, nil
	}
	if runtime.GOOS == "windows" {
		return nil, fmt.Errorf("secretrender: template %s owner and group are POSIX ownership; on Windows the file's DACL names who reads it", t.Name)
	}
	if effectiveUID() != 0 {
		return nil, fmt.Errorf("secretrender: template %s gives its file to owner %q group %q, which needs the agent to run as root", t.Name, t.Owner, t.Group)
	}
	own := &fileOwnership{uid: -1, gid: -1}
	if t.Owner != "" {
		uid, err := lookupID(t.Owner, func(name string) (string, error) {
			u, err := user.Lookup(name)
			if err != nil {
				return "", err
			}
			return u.Uid, nil
		})
		if err != nil {
			return nil, fmt.Errorf("secretrender: template %s owner %q: %w", t.Name, t.Owner, err)
		}
		own.uid = uid
	}
	if t.Group != "" {
		gid, err := lookupID(t.Group, func(name string) (string, error) {
			g, err := user.LookupGroup(name)
			if err != nil {
				return "", err
			}
			return g.Gid, nil
		})
		if err != nil {
			return nil, fmt.Errorf("secretrender: template %s group %q: %w", t.Name, t.Group, err)
		}
		own.gid = gid
	}
	return own, nil
}

// lookupID is a numeric ID as written, or the ID the system database gives
// the name.
func lookupID(nameOrID string, lookup func(string) (string, error)) (int, error) {
	if id, err := strconv.Atoi(nameOrID); err == nil {
		if id < 0 {
			return 0, fmt.Errorf("a numeric ID is 0 or more")
		}
		return id, nil
	}
	raw, err := lookup(nameOrID)
	if err != nil {
		return 0, err
	}
	id, err := strconv.Atoi(raw)
	if err != nil || id < 0 {
		return 0, fmt.Errorf("the system gives %q no numeric ID", nameOrID)
	}
	return id, nil
}
