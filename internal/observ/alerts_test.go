package observ_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"trustctl.io/trustctl/internal/observ"
)

// TestAlertRulesReferenceRealMetrics is the R2.2 "a sample alert fires under an
// induced condition" reality check: every trustctl_ metric the shipped Prometheus
// alert rules reference is actually emitted by the running code, and inducing the
// alert's condition (a 5xx response) moves the metric it watches. A rule that
// referenced a non-existent metric would never fire — this catches that.
func TestAlertRulesReferenceRealMetrics(t *testing.T) {
	data, err := os.ReadFile(filepath.FromSlash("../../deploy/observability/alerts.yml"))
	if err != nil {
		t.Fatalf("read alerts.yml: %v", err)
	}
	refs := uniqueStrings(regexp.MustCompile(`trustctl_[a-z0-9_]+`).FindAllString(string(data), -1))
	if len(refs) == 0 {
		t.Fatal("alerts.yml references no trustctl_ metrics")
	}

	// Induce the alert condition: a request that returns 5xx.
	reg := observ.NewRegistry()
	mw := observ.NewMiddleware(observ.Options{Registry: reg, Tracer: observ.NewTracer(nil)})
	h := mw.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/owners", nil))

	// Induce the signer alert condition through the shared library (SF.3): a signer
	// that is down after several restarts emits both signer metrics the
	// trustctl-signer rules watch.
	observ.NewSignerMetrics(reg).Observe(false, 4)

	var sb strings.Builder
	if err := reg.WriteProm(&sb); err != nil {
		t.Fatal(err)
	}
	emitted := sb.String()
	for _, m := range refs {
		if !strings.Contains(emitted, m) {
			t.Errorf("alerts.yml references metric %q that the code does not emit", m)
		}
	}
	// The induced 5xx is observable in the metric the error-rate alert watches.
	if !strings.Contains(emitted, `trustctl_http_requests_total{method="GET",route="/api/v1/owners",code="500"} 1`) {
		t.Errorf("the induced 5xx did not increment the error counter:\n%s", emitted)
	}
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
