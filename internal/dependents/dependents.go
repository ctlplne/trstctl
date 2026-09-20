// SPDX-License-Identifier: BUSL-1.1

// Package dependents defines a feature-neutral hook vocabulary for recording
// objects whose validity or confidentiality depends on another key.
package dependents

import "context"

type Kind string

const (
	KindCredential   Kind = "credential"
	KindLeasedSecret Kind = "leased_secret"
)

// Record is non-secret metadata about one newly-created dependent object.
type Record struct {
	TenantID         string
	ProtectedByKeyID string
	Kind             Kind
	DependentID      string
	IdempotencyKey   string
	Source           string
	Metadata         map[string]string
}

type Recorder interface {
	RecordDependent(context.Context, Record) error
}

type RecorderFunc func(context.Context, Record) error

func (f RecorderFunc) RecordDependent(ctx context.Context, rec Record) error {
	return f(ctx, rec)
}
