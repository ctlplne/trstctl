// Package tenancy contains core tenant-routing vocabulary and inert defaults.
//
// Provider-tier code can install a router through SetRouter. Core callers still
// keep the AN-1 guarantees: routing errors fail closed, and pooled routing is the
// default when no edition code is attached.
package tenancy

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

type IsolationModel string

const (
	IsolationPooled IsolationModel = "pooled"
	IsolationSiloed IsolationModel = "siloed"
	IsolationHybrid IsolationModel = "hybrid"
)

type Targets struct {
	Model                IsolationModel
	PostgresSchema       string
	JetStreamSubjectLane string
	ObjectKeyPrefix      string
}

type Router interface {
	TargetsFor(ctx context.Context, tenantID string) (Targets, error)
	JetStreamSubjectLanes(ctx context.Context) ([]string, error)
}

type PooledRouter struct{}

func (PooledRouter) TargetsFor(context.Context, string) (Targets, error) {
	return Targets{Model: IsolationPooled}, nil
}

func (PooledRouter) JetStreamSubjectLanes(context.Context) ([]string, error) {
	return nil, nil
}

var (
	routerMu sync.RWMutex
	router   Router = PooledRouter{}
)

func SetRouter(r Router) {
	if r == nil {
		r = PooledRouter{}
	}
	routerMu.Lock()
	router = r
	routerMu.Unlock()
}

func CurrentRouter() Router {
	routerMu.RLock()
	defer routerMu.RUnlock()
	return router
}

var (
	pgIdentRe      = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)
	subjectTokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

func ValidIsolationModel(model string) bool {
	switch IsolationModel(model) {
	case "", IsolationPooled, IsolationSiloed, IsolationHybrid:
		return true
	default:
		return false
	}
}

func PostgresSchema(ctx context.Context, tenantID string) (string, error) {
	targets, err := CurrentRouter().TargetsFor(ctx, tenantID)
	if err != nil {
		return "", fmt.Errorf("tenancy: resolve postgres route for %s: %w", tenantID, err)
	}
	if targets.PostgresSchema == "" {
		return "", nil
	}
	if !pgIdentRe.MatchString(targets.PostgresSchema) {
		return "", fmt.Errorf("tenancy: refusing malformed postgres schema %q", targets.PostgresSchema)
	}
	return targets.PostgresSchema, nil
}

func EventSubject(ctx context.Context, tenantID, prefix, eventType string) (string, error) {
	targets, err := CurrentRouter().TargetsFor(ctx, tenantID)
	if err != nil {
		return "", fmt.Errorf("tenancy: resolve JetStream route for %s: %w", tenantID, err)
	}
	prefix = strings.Trim(prefix, ".")
	eventType = strings.Trim(eventType, ".")
	if prefix == "" || eventType == "" {
		return "", fmt.Errorf("tenancy: event subject requires prefix and event type")
	}
	if targets.JetStreamSubjectLane == "" {
		return prefix + "." + eventType, nil
	}
	if err := validateSubjectLane(targets.JetStreamSubjectLane); err != nil {
		return "", err
	}
	return prefix + "." + targets.JetStreamSubjectLane + "." + eventType, nil
}

func ObjectPrefix(ctx context.Context, tenantID string) (string, error) {
	targets, err := CurrentRouter().TargetsFor(ctx, tenantID)
	if err != nil {
		return "", fmt.Errorf("tenancy: resolve object route for %s: %w", tenantID, err)
	}
	if targets.ObjectKeyPrefix == "" {
		return "tenant/" + strings.Trim(tenantID, "/") + "/", nil
	}
	if err := validateObjectPrefix(targets.ObjectKeyPrefix); err != nil {
		return "", err
	}
	return targets.ObjectKeyPrefix, nil
}

func validateSubjectLane(lane string) error {
	for _, token := range strings.Split(lane, ".") {
		if !subjectTokenRe.MatchString(token) {
			return fmt.Errorf("tenancy: refusing malformed JetStream subject lane %q", lane)
		}
	}
	return nil
}

func validateObjectPrefix(prefix string) error {
	if strings.HasPrefix(prefix, "/") || strings.Contains(prefix, "..") || strings.Contains(prefix, "\x00") {
		return fmt.Errorf("tenancy: refusing malformed object prefix %q", prefix)
	}
	if !strings.HasSuffix(prefix, "/") {
		return fmt.Errorf("tenancy: object prefix %q must end with slash", prefix)
	}
	return nil
}
