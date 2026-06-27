package observ

// OCSPMetrics records low-cardinality served OCSP counters. Labels are per
// issuer/CA and outcome only; no tenant, serial, fingerprint, or nonce values are
// exposed.
type OCSPMetrics struct {
	requests *CounterVec
	cache    *CounterVec
	nonce    *CounterVec
}

// NewOCSPMetrics registers the served OCSP counters on r.
func NewOCSPMetrics(r *Registry) *OCSPMetrics {
	if r == nil {
		return nil
	}
	return &OCSPMetrics{
		requests: r.CounterVec("trstctl_ocsp_responses_total",
			"Served OCSP responses by CA and result.", []string{"ca_id", "result"}),
		cache: r.CounterVec("trstctl_ocsp_response_cache_total",
			"Served OCSP response cache lookups by CA and result.", []string{"ca_id", "result"}),
		nonce: r.CounterVec("trstctl_ocsp_nonce_total",
			"Served OCSP nonce handling by CA and result.", []string{"ca_id", "result"}),
	}
}

func (m *OCSPMetrics) ObserveResponse(caID, result string) {
	if m == nil || m.requests == nil {
		return
	}
	m.requests.WithLabelValues(caID, result).Inc()
}

func (m *OCSPMetrics) ObserveCache(caID, result string) {
	if m == nil || m.cache == nil {
		return
	}
	m.cache.WithLabelValues(caID, result).Inc()
}

func (m *OCSPMetrics) ObserveNonce(caID, result string) {
	if m == nil || m.nonce == nil {
		return
	}
	m.nonce.WithLabelValues(caID, result).Inc()
}
