package helm

import "testing"

func TestServiceMonitorAndScrapeAnnotationsRenderMetricsEndpoint(t *testing.T) {
	v := serviceMonitorValues()

	service := renderSimpleObj(t, "service.yaml", v)
	metadata := mustMap(t, service, "metadata")
	annotations := mustMap(t, metadata, "annotations")
	for key, want := range map[string]string{
		"prometheus.io/scrape":                              "true",
		"prometheus.io/scheme":                              "https",
		"prometheus.io/path":                                "/metrics",
		"prometheus.io/port":                                "8443",
		"service.beta.kubernetes.io/aws-load-balancer-type": "nlb",
	} {
		if got := asString(annotations[key]); got != want {
			t.Fatalf("Service annotation %s = %q, want %q", key, got, want)
		}
	}

	rendered := renderChartFile(t, "servicemonitor.yaml", v)
	objs := decodeAllYAML(t, rendered)
	if len(objs) != 1 {
		t.Fatalf("ServiceMonitor template rendered %d objects, want 1:\n%s", len(objs), rendered)
	}
	sm := objs[0]
	if got := asString(sm["apiVersion"]); got != "monitoring.coreos.com/v1" {
		t.Fatalf("ServiceMonitor apiVersion = %q, want monitoring.coreos.com/v1", got)
	}
	if got := asString(sm["kind"]); got != "ServiceMonitor" {
		t.Fatalf("ServiceMonitor kind = %q, want ServiceMonitor", got)
	}

	smMeta := mustMap(t, sm, "metadata")
	if got := asString(smMeta["namespace"]); got != "observability" {
		t.Fatalf("ServiceMonitor namespace = %q, want observability", got)
	}
	labels := mustMap(t, smMeta, "labels")
	if got := asString(labels["release"]); got != "kube-prometheus-stack" {
		t.Fatalf("ServiceMonitor release label = %q, want kube-prometheus-stack", got)
	}
	smAnnotations := mustMap(t, smMeta, "annotations")
	if got := asString(smAnnotations["trstctl.com/scrape-owner"]); got != "platform-observability" {
		t.Fatalf("ServiceMonitor scrape-owner annotation = %q", got)
	}

	spec := mustMap(t, sm, "spec")
	selector := mustMap(t, spec, "selector")
	matchLabels := mustMap(t, selector, "matchLabels")
	for key, want := range map[string]string{
		"app.kubernetes.io/name":      "trstctl",
		"app.kubernetes.io/instance":  "trstctl",
		"app.kubernetes.io/component": "control-plane",
	} {
		if got := asString(matchLabels[key]); got != want {
			t.Fatalf("ServiceMonitor selector %s = %q, want %q", key, got, want)
		}
	}
	namespaceSelector := mustMap(t, spec, "namespaceSelector")
	matchNames, _ := namespaceSelector["matchNames"].([]any)
	if len(matchNames) != 1 || asString(matchNames[0]) != "trstctl" {
		t.Fatalf("ServiceMonitor namespaceSelector.matchNames = %#v, want [trstctl]", matchNames)
	}

	endpoints := asMaps(spec["endpoints"])
	if len(endpoints) != 1 {
		t.Fatalf("ServiceMonitor endpoints = %#v, want one endpoint", spec["endpoints"])
	}
	endpoint := endpoints[0]
	for key, want := range map[string]string{
		"port":          "https",
		"path":          "/metrics",
		"scheme":        "https",
		"interval":      "30s",
		"scrapeTimeout": "10s",
	} {
		if got := asString(endpoint[key]); got != want {
			t.Fatalf("ServiceMonitor endpoint %s = %q, want %q", key, got, want)
		}
	}
	tlsConfig := mustMap(t, endpoint, "tlsConfig")
	if got, _ := tlsConfig["insecureSkipVerify"].(bool); !got {
		t.Fatalf("ServiceMonitor tlsConfig.insecureSkipVerify = %#v, want true for the configured eval/self-signed TLS scrape", tlsConfig["insecureSkipVerify"])
	}
}

func serviceMonitorValues() map[string]any {
	v := defaultishValues()
	v["service"] = map[string]any{
		"type": "ClusterIP",
		"port": 8443,
		"annotations": map[string]any{
			"service.beta.kubernetes.io/aws-load-balancer-type": "nlb",
		},
	}
	v["metrics"] = map[string]any{
		"serviceAnnotations": map[string]any{
			"enabled": true,
			"path":    "/metrics",
			"scheme":  "https",
			"port":    "",
		},
		"serviceMonitor": map[string]any{
			"enabled":       true,
			"namespace":     "observability",
			"interval":      "30s",
			"scrapeTimeout": "10s",
			"path":          "/metrics",
			"scheme":        "https",
			"portName":      "https",
			"labels": map[string]any{
				"release": "kube-prometheus-stack",
			},
			"annotations": map[string]any{
				"trstctl.com/scrape-owner": "platform-observability",
			},
			"tlsConfig": map[string]any{
				"insecureSkipVerify": true,
			},
		},
	}
	return v
}

func mustMap(t *testing.T, obj map[string]any, key string) map[string]any {
	t.Helper()
	m, ok := obj[key].(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v (%T), want map", key, obj[key], obj[key])
	}
	return m
}
