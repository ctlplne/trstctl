package elasticsearch_test

import (
	"bytes"
	"context"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/elasticsearch"
)

var (
	elasticCert = []byte("-----BEGIN CERTIFICATE-----\nelasticsearch-leaf\n-----END CERTIFICATE-----\n")
	elasticKey  = []byte("-----BEGIN PRIVATE KEY-----\nelasticsearch-key\n-----END PRIVATE KEY-----\n")
)

func TestDeployWritesWatchedTLSFiles(t *testing.T) {
	ops := connector.NewMemoryOps()
	c := elasticsearch.New("/etc/elasticsearch/certs/http.crt", "/etc/elasticsearch/certs/http.key")
	if _, err := connector.Run(context.Background(), c, ops, connector.NewDeployment("elasticsearch", elasticCert, elasticKey)); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	if got, ok := ops.File("/etc/elasticsearch/certs/http.crt"); !ok || !bytes.Equal(got, elasticCert) {
		t.Fatal("certificate was not written")
	}
	if got, ok := ops.File("/etc/elasticsearch/certs/http.key"); !ok || !bytes.Equal(got, elasticKey) {
		t.Fatal("key was not written")
	}
	if got := ops.Execs(); len(got) != 0 {
		t.Fatalf("elasticsearch connector should use watched files, got execs: %+v", got)
	}
}

func TestElasticsearchPassesConformance(t *testing.T) {
	rep := connector.Conformance(context.Background(), elasticsearch.New("/etc/elasticsearch/certs/http.crt", "/etc/elasticsearch/certs/http.key"))
	if !rep.OK() {
		for _, ch := range rep.Checks {
			if !ch.Passed {
				t.Errorf("conformance %q failed: %s", ch.Name, ch.Detail)
			}
		}
	}
}
