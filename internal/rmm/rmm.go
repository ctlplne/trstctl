// SPDX-License-Identifier: BUSL-1.1

// Package rmm holds the vendor clients the Provider plane runs the trstctl
// agent's lifecycle through on a customer's devices (MSP-9 onward): list the
// devices under the customer's RMM organization, run the configured install,
// upgrade or remove script on one of them, and report the agent's health
// back to the device. A client only translates: the core decides which
// customer a device belongs to, refuses a device the RMM does not list under
// the customer's own organization, and mints the one-time enrollment token
// for the customer's own tenant at the moment of delivery.
package rmm

import (
	"context"
	"errors"
)

// Device is one device the RMM manages.
type Device struct {
	ID     string
	OrgID  string
	Name   string
	Online bool
}

// Action is an agent lifecycle action run through the RMM.
type Action string

// The agent lifecycle actions.
const (
	ActionInstall Action = "install"
	ActionUpgrade Action = "upgrade"
	ActionRemove  Action = "remove"
)

// Valid reports whether a is a known action.
func (a Action) Valid() bool {
	return a == ActionInstall || a == ActionUpgrade || a == ActionRemove
}

// InstallParams are what an install script receives: where the agent
// enrolls, the identity it enrolls as, and the one-time bootstrap token for
// the customer's tenant. Token is borrowed; the caller wipes it.
type InstallParams struct {
	Server     string
	ServerName string
	Identity   string
	Token      []byte
}

// Client is what the Provider plane needs from an RMM.
type Client interface {
	// ListDevices lists the devices under an organization.
	ListDevices(ctx context.Context, orgID string) ([]Device, error)
	// Device reads one device; found is false when the RMM has none.
	Device(ctx context.Context, deviceID string) (Device, bool, error)
	// RunAction runs the action's script on the device and returns the
	// RMM's job ID when it answers one.
	RunAction(ctx context.Context, deviceID string, action Action, install *InstallParams) (string, error)
	// ReportHealth writes the agent's health summary to the device.
	ReportHealth(ctx context.Context, deviceID, summary string) error
}

// ErrBeforeWrite marks a failure proven before anything reached the RMM's
// device (a lookup, a sign-in, a refusal of the request itself).
var ErrBeforeWrite = errors.New("rmm: refused before anything ran")

// ErrRefused marks the RMM's definitive refusal of a write.
var ErrRefused = errors.New("rmm: the RMM refused the request")

// AppendJSONString writes src as a JSON string onto dst byte by byte, so a
// credential never becomes a Go string that cannot be wiped.
func AppendJSONString(dst, src []byte) []byte {
	const hex = "0123456789abcdef"
	dst = append(dst, '"')
	for _, b := range src {
		switch {
		case b == '"' || b == '\\':
			dst = append(dst, '\\', b)
		case b < 0x20:
			dst = append(dst, '\\', 'u', '0', '0', hex[b>>4], hex[b&15])
		default:
			dst = append(dst, b)
		}
	}
	return append(dst, '"')
}

// AppendFormEscaped form-encodes src onto dst byte by byte.
func AppendFormEscaped(dst, src []byte) []byte {
	const hex = "0123456789ABCDEF"
	for _, b := range src {
		switch {
		case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9', b == '-', b == '_', b == '.', b == '~':
			dst = append(dst, b)
		case b == ' ':
			dst = append(dst, '+')
		default:
			dst = append(dst, '%', hex[b>>4], hex[b&15])
		}
	}
	return dst
}
