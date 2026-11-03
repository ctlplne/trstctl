// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"sort"

	"trstctl.com/trstctl/internal/api"
)

// OperationsHealth measures the deployment for the operations dashboard
// (A246): every readiness probe's verdict, the event log's head and the read
// model's applied and failed positions — the same reads /readyz makes.
func (s *Server) OperationsHealth(ctx context.Context) (api.OperationsHealth, error) {
	var out api.OperationsHealth
	if s.readiness != nil {
		_, results, _ := s.readiness.EvaluateDetailed(ctx)
		names := make([]string, 0, len(results))
		for name := range results {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			dep := api.OperationsDependency{Name: name, Healthy: results[name] == "ok"}
			if !dep.Healthy {
				dep.Detail = results[name]
			}
			out.Dependencies = append(out.Dependencies, dep)
		}
	}
	if s.log != nil {
		head, err := s.log.LastSequence(ctx)
		if err != nil {
			return api.OperationsHealth{}, err
		}
		out.EventHead = head
	}
	if s.store != nil {
		tail, err := s.store.ProjectionTailHealth(ctx)
		if err != nil {
			return api.OperationsHealth{}, err
		}
		out.ProjectionApplied, out.ProjectionFailed = tail.AppliedSequence, tail.FailedSequence
	}
	return out, nil
}
