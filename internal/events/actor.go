package events

import "context"

// Actor identifies the authenticated caller responsible for an event — the "who"
// of the who-did-what-when-under-what-authorization audit trail (R2.1, F9). It is
// recorded on every event appended under a request context that carries it;
// background or system appends leave it nil (honestly unattributed rather than
// fabricated).
type Actor struct {
	Subject string   `json:"subject"`         // authenticated subject (token subject or OIDC sub)
	Roles   []string `json:"roles,omitempty"` // role names the subject acted under (the "authorization")
}

type actorCtxKey struct{}

// ContextWithActor returns a context that attributes events appended under it to
// a. The API sets this from the resolved principal so the orchestrator's commands
// — which all funnel through Append — record the actor without threading it
// through every signature.
func ContextWithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, actorCtxKey{}, a)
}

// ActorFromContext returns the actor carried by ctx, if one was set.
func ActorFromContext(ctx context.Context) (Actor, bool) {
	a, ok := ctx.Value(actorCtxKey{}).(Actor)
	return a, ok
}
