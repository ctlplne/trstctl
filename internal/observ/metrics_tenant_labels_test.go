// SPDX-License-Identifier: BUSL-1.1

package observ_test

import (
	"fmt"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/observ"
)

// F270: the registry renders to the unauthenticated /metrics endpoint, so no
// vector may label its series by tenant. The refusal lives in the registry
// itself so every caller (core, EE, connectors) is covered, including metrics
// registered under a variable name or label list.
func TestRegistryRefusesTenantLabels(t *testing.T) {
	register := map[string]func(*observ.Registry, []string){
		"counter": func(r *observ.Registry, l []string) { r.CounterVec("trstctl_probe_total", "probe", l) },
		"gauge":   func(r *observ.Registry, l []string) { r.GaugeVec("trstctl_probe", "probe", l) },
		"histogram": func(r *observ.Registry, l []string) {
			r.HistogramVec("trstctl_probe_seconds", "probe", []float64{1}, l)
		},
	}
	for kind, reg := range register {
		for _, labels := range [][]string{{"tenant_id"}, {"destination", "Tenant"}, {"owner_tenant"}} {
			t.Run(fmt.Sprintf("%s/%s", kind, strings.Join(labels, ",")), func(t *testing.T) {
				defer func() {
					got := recover()
					if got == nil {
						t.Fatalf("registry accepted tenant label %v on the unauthenticated /metrics endpoint", labels)
					}
					if msg := fmt.Sprint(got); !strings.Contains(msg, "unauthenticated /metrics") {
						t.Fatalf("refusal does not say why: %s", msg)
					}
				}()
				reg(observ.NewRegistry(), labels)
			})
		}
		t.Run(kind+"/non-tenant labels still register", func(t *testing.T) {
			reg(observ.NewRegistry(), []string{"destination", "result"})
		})
	}
}
