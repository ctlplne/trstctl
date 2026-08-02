// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reducers

import (
	"context"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/pluginhost"
)

type capability = pluginhost.Capability

const (
	CapObserveList      Capability = "observe.list"
	CapObserveDescribe  Capability = "observe.describe"
	CapObserveSubscribe Capability = "observe.subscribe"
	CapObserveMutate    Capability = "observe.mutate"
)

type OperationKind string

const (
	OpList      OperationKind = "list"
	OpDescribe  OperationKind = "describe"
	OpSubscribe OperationKind = "subscribe"
	OpMutate    OperationKind = "mutate"
)

type AuthorityOperation struct {
	Kind     OperationKind
	Resource string
	Cursor   string
	Payload  []byte
}

type AuthorityTransport interface {
	DoObservation(ctx context.Context, op AuthorityOperation) ([]byte, error)
}

type ObservationSandbox struct {
	grant     Grant
	transport AuthorityTransport
	denied    int
}

// ReadOnlyObservationGrant is the only grant an observation reducer may hold: it
// permits reads of a foreign authority and nothing else (XREC-claim-8).
func ReadOnlyObservationGrant(scope string) pluginhost.Grant {
	g := pluginhost.NewGrant(CapObserveList, CapObserveDescribe, CapObserveSubscribe)
	prefix := resourcePrefix(scope)
	if prefix == "" {
		return g
	}
	for _, cap := range []Capability{CapObserveList, CapObserveDescribe, CapObserveSubscribe} {
		g = g.WithPathPrefix(cap, prefix)
	}
	return g
}

func NewObservationSandbox(grant Grant, transport AuthorityTransport) *ObservationSandbox {
	if grant == nil || grant.Empty() {
		grant = ReadOnlyObservationGrant("")
	}
	if transport == nil {
		transport = noopTransport{}
	}
	return &ObservationSandbox{grant: grant, transport: transport}
}

func (s *ObservationSandbox) List(ctx context.Context, resource string) ([]byte, error) {
	return s.do(ctx, CapObserveList, AuthorityOperation{Kind: OpList, Resource: resource})
}

func (s *ObservationSandbox) Describe(ctx context.Context, resource string) ([]byte, error) {
	return s.do(ctx, CapObserveDescribe, AuthorityOperation{Kind: OpDescribe, Resource: resource})
}

func (s *ObservationSandbox) Subscribe(ctx context.Context, resource, cursor string) ([]byte, error) {
	return s.do(ctx, CapObserveSubscribe, AuthorityOperation{Kind: OpSubscribe, Resource: resource, Cursor: cursor})
}

func (s *ObservationSandbox) Mutate(ctx context.Context, resource string, payload []byte) error {
	_, err := s.do(ctx, CapObserveMutate, AuthorityOperation{Kind: OpMutate, Resource: resource, Payload: append([]byte(nil), payload...)})
	return err
}

func (s *ObservationSandbox) Denied() int { return s.denied }

func (s *ObservationSandbox) do(ctx context.Context, cap Capability, op AuthorityOperation) ([]byte, error) {
	if !s.grant.Allows(cap, op.Resource) {
		s.denied++
		return nil, connector.ErrDenied
	}
	return s.transport.DoObservation(ctx, op)
}

type noopTransport struct{}

func (noopTransport) DoObservation(context.Context, AuthorityOperation) ([]byte, error) {
	return nil, nil
}

func resourcePrefix(scope string) string {
	scope = strings.TrimRight(strings.TrimSpace(scope), "/")
	if scope == "" {
		return ""
	}
	return scope + "/"
}
