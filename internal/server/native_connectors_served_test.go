package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/a10"
	"trstctl.com/trstctl/internal/connector/a10/a10test"
	"trstctl.com/trstctl/internal/connector/acm"
	"trstctl.com/trstctl/internal/connector/acm/acmtest"
	"trstctl.com/trstctl/internal/connector/azurekv"
	"trstctl.com/trstctl/internal/connector/azurekv/azurekvtest"
	"trstctl.com/trstctl/internal/connector/elasticsearch"
	"trstctl.com/trstctl/internal/connector/kemp"
	"trstctl.com/trstctl/internal/connector/kemp/kemptest"
	"trstctl.com/trstctl/internal/connector/mysql"
	"trstctl.com/trstctl/internal/connector/postgresql"
	"trstctl.com/trstctl/internal/connector/rabbitmq"
	"trstctl.com/trstctl/internal/connector/tomcat"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
)

func TestServedNativeConnectorRegistryDeploysToACMAndAzureKVEmulators(t *testing.T) {
	const (
		awsAccessKey = "AKIDCLM05"
		awsSecretKey = "CLM05SecretKeyForSigV4Only"
		acmTargetARN = "arn:aws:acm:us-east-1:123456789012:certificate/clm-05"
		azureToken   = "clm-05-azure-token"
		azureCert    = "clm-05-web"
	)

	acmSrv := acmtest.New(awsAccessKey, awsSecretKey)
	defer acmSrv.Close()
	kvSrv := azurekvtest.New(azureToken)
	defer kvSrv.Close()

	reg := connector.NewRegistry(func(name string) connector.Ops {
		switch name {
		case "aws-acm":
			return connector.NewHTTPOps(acmSrv.Client())
		case "azure-keyvault":
			return connector.NewHTTPOps(kvSrv.Client())
		default:
			return connector.NewHTTPOps(nil)
		}
	})
	reg.Register(acm.New("us-east-1", acm.Credentials{
		AccessKeyID:     awsAccessKey,
		SecretAccessKey: []byte(awsSecretKey),
	}, acm.WithEndpoint(acmSrv.URL())))
	reg.Register(azurekv.New(kvSrv.URL(), azurekv.StaticToken([]byte(azureToken))))

	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ConnectorRegistry = reg
	})
	tok := seedScopedToken(t, h.store, h.tenant, "connectors:read")

	certPEM, keyPEM := servedNativeDeployCredential(t, h, "clm-05.served.test")
	defer secret.Wipe(keyPEM)
	if err := crypto.VerifyCertKeyMatchPEM(certPEM, keyPEM); err != nil {
		t.Fatalf("test credential mismatch: %v", err)
	}

	enqueueServedConnectorDeploy(t, h, "clm-05-acm", "aws-acm", connector.NewDeployment(acmTargetARN, certPEM, keyPEM))
	enqueueServedConnectorDeploy(t, h, "clm-05-azure-kv", "azure-keyvault", connector.NewDeployment(azureCert, certPEM, keyPEM))
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain native connector outbox: %v", err)
	}

	acmImport, ok := acmSrv.Imported(acmTargetARN)
	if !ok {
		t.Fatalf("served aws-acm deploy did not import into the ACM emulator")
	}
	if !bytes.Equal(acmImport.Certificate, certPEM) || !bytes.Equal(acmImport.PrivateKey, keyPEM) {
		t.Fatalf("ACM emulator received the wrong credential")
	}
	kvImport, ok := kvSrv.Imported(azureCert)
	if !ok {
		t.Fatalf("served azure-keyvault deploy did not import into the Key Vault emulator")
	}
	if !bytes.Contains(kvImport.PEM, keyPEM) || !bytes.Contains(kvImport.PEM, certPEM) {
		t.Fatalf("Key Vault emulator received bundle without the issued cert and key")
	}

	deliveries := connectorDeliveries(t, h, tok)
	want := map[string]string{
		"aws-acm":        acmTargetARN,
		"azure-keyvault": azureCert,
	}
	for _, got := range deliveries.Items {
		if want[got.Connector] != got.Target {
			continue
		}
		if got.Status != "delivered" || got.Reason != "native_delivered" || got.Fingerprint == "" {
			t.Fatalf("bad native connector receipt for %s: %+v", got.Connector, got)
		}
		delete(want, got.Connector)
	}
	if len(want) != 0 {
		t.Fatalf("missing delivered connector receipts for %+v; got %s", want, deliveries.Raw)
	}
	if !h.hasEvent(t, "connector.delivery.recorded") {
		t.Fatal("native connector deployment did not emit connector.delivery.recorded")
	}
}

func TestServedLoadBalancerConnectorBreadthCAPDEP01(t *testing.T) {
	const (
		a10User   = "admin"
		a10Pass   = "a10-secret"
		a10Target = "payments-client-ssl"
		kempToken = "kemp-token"
		kempVS    = "vs-payments-443"
	)

	a10Srv := a10test.New(a10User, a10Pass)
	defer a10Srv.Close()
	kempSrv := kemptest.New(kempToken)
	defer kempSrv.Close()

	reg := connector.NewRegistry(func(name string) connector.Ops {
		switch name {
		case "a10":
			return connector.NewHTTPOps(a10Srv.Client())
		case "kemp":
			return connector.NewHTTPOps(kempSrv.Client())
		default:
			return connector.NewHTTPOps(nil)
		}
	})
	reg.Register(a10.New(a10Srv.URL(), a10User, []byte(a10Pass)))
	reg.Register(kemp.New(kempSrv.URL(), []byte(kempToken)))

	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ConnectorRegistry = reg
	})
	tok := seedScopedToken(t, h.store, h.tenant, "connectors:read", "connectors:write")

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/connectors/catalog", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("connector catalog: status %d body %s", status, body)
	}
	for _, want := range []string{`"name":"f5"`, `"name":"netscaler"`, `"name":"a10"`, `"name":"kemp"`} {
		if !jsonContains(t, body, want) {
			t.Fatalf("connector catalog missing %s: %s", want, body)
		}
	}

	for _, tc := range []struct {
		name      string
		connector string
		target    string
	}{
		{name: "dc1/a10/payments", connector: "a10", target: a10Target},
		{name: "dc1/kemp/payments", connector: "kemp", target: kempVS},
	} {
		status, body = secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets", tok, map[string]any{
			"name":      tc.name,
			"connector": tc.connector,
			"config": map[string]any{
				"target":         tc.target,
				"credential_ref": "secret://connectors/" + tc.connector + "/payments",
			},
		})
		if status != http.StatusCreated {
			t.Fatalf("create %s target: status %d body %s", tc.connector, status, body)
		}
	}

	certPEM, keyPEM := servedNativeDeployCredential(t, h, "cap-dep-01.served.test")
	defer secret.Wipe(keyPEM)
	enqueueServedConnectorDeploy(t, h, "cap-dep-01-a10", "a10", connector.NewDeployment(a10Target, certPEM, keyPEM))
	enqueueServedConnectorDeploy(t, h, "cap-dep-01-kemp", "kemp", connector.NewDeployment(kempVS, certPEM, keyPEM))
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain load-balancer connector outbox: %v", err)
	}

	a10Binding, ok := a10Srv.Binding(a10Target)
	if !ok || !bytes.Equal(a10Binding.Certificate, certPEM) || !bytes.Equal(a10Binding.PrivateKey, keyPEM) {
		t.Fatalf("A10 connector did not bind the renewed credential: %+v ok=%v", a10Binding, ok)
	}
	kempBinding, ok := kempSrv.Binding(kempVS)
	if !ok || !bytes.Equal(kempBinding.Certificate, certPEM) || !bytes.Equal(kempBinding.PrivateKey, keyPEM) {
		t.Fatalf("Kemp connector did not bind the renewed credential: %+v ok=%v", kempBinding, ok)
	}

	deliveries := connectorDeliveries(t, h, tok)
	want := map[string]string{"a10": a10Target, "kemp": kempVS}
	for _, got := range deliveries.Items {
		if want[got.Connector] != got.Target {
			continue
		}
		if got.Status != "delivered" || got.Reason != "native_delivered" || got.Fingerprint == "" {
			t.Fatalf("bad load-balancer connector receipt for %s: %+v", got.Connector, got)
		}
		delete(want, got.Connector)
	}
	if len(want) != 0 {
		t.Fatalf("missing delivered load-balancer connector receipts for %+v; got %s", want, deliveries.Raw)
	}
}

func TestServedPublishedConnectorCatalogCAPDEP09(t *testing.T) {
	type targetSpec struct {
		name     string
		certPath string
		keyPath  string
	}
	specs := []targetSpec{
		{name: "postgresql", certPath: "/etc/postgresql/tls/server.crt", keyPath: "/etc/postgresql/tls/server.key"},
		{name: "mysql", certPath: "/etc/mysql/tls/server-cert.pem", keyPath: "/etc/mysql/tls/server-key.pem"},
		{name: "rabbitmq", certPath: "/etc/rabbitmq/tls/server.crt", keyPath: "/etc/rabbitmq/tls/server.key"},
		{name: "elasticsearch", certPath: "/etc/elasticsearch/certs/http.crt", keyPath: "/etc/elasticsearch/certs/http.key"},
		{name: "tomcat", certPath: "/etc/tomcat/tls/server.crt", keyPath: "/etc/tomcat/tls/server.key"},
	}
	opsByName := map[string]*connector.MemoryOps{}
	for _, spec := range specs {
		opsByName[spec.name] = connector.NewMemoryOps()
	}
	reg := connector.NewRegistry(func(name string) connector.Ops {
		return opsByName[name]
	})
	reg.Register(postgresql.New(specs[0].certPath, specs[0].keyPath))
	reg.Register(mysql.New(specs[1].certPath, specs[1].keyPath))
	reg.Register(rabbitmq.New(specs[2].certPath, specs[2].keyPath))
	reg.Register(elasticsearch.New(specs[3].certPath, specs[3].keyPath))
	reg.Register(tomcat.New(specs[4].certPath, specs[4].keyPath))

	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ConnectorRegistry = reg
	})
	tok := seedScopedToken(t, h.store, h.tenant, "connectors:read", "connectors:write")

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/connectors/catalog", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("connector catalog: status %d body %s", status, body)
	}
	var catalog struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &catalog); err != nil {
		t.Fatalf("decode catalog: %v body %s", err, body)
	}
	if got, want := len(catalog.Items), 24; got < want {
		t.Fatalf("published connector catalog has %d entries, want at least %d: %s", got, want, body)
	}
	catalogBody := body
	for _, spec := range specs {
		if !jsonContains(t, catalogBody, `"name":"`+spec.name+`"`) {
			t.Fatalf("connector catalog missing %q: %s", spec.name, catalogBody)
		}
		status, body = secretsReq(t, h, http.MethodPost, "/api/v1/connectors/targets", tok, map[string]any{
			"name":      "catalog/" + spec.name + "/prod",
			"connector": spec.name,
			"config": map[string]any{
				"credential_ref": "secret://connectors/" + spec.name + "/prod",
				"cert_path":      spec.certPath,
				"key_path":       spec.keyPath,
			},
		})
		if status != http.StatusCreated {
			t.Fatalf("create %s target: status %d body %s", spec.name, status, body)
		}
	}

	certPEM, keyPEM := servedNativeDeployCredential(t, h, "cap-dep-09.served.test")
	defer secret.Wipe(keyPEM)
	for _, spec := range specs {
		enqueueServedConnectorDeploy(t, h, "cap-dep-09-"+spec.name, spec.name, connector.NewDeployment("prod", certPEM, keyPEM))
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain published connector catalog outbox: %v", err)
	}
	for _, spec := range specs {
		ops := opsByName[spec.name]
		gotCert, ok := ops.File(spec.certPath)
		if !ok || !bytes.Equal(gotCert, certPEM) {
			t.Fatalf("%s did not write certificate to %s", spec.name, spec.certPath)
		}
		gotKey, ok := ops.File(spec.keyPath)
		if !ok || !bytes.Equal(gotKey, keyPEM) {
			t.Fatalf("%s did not write private key to %s", spec.name, spec.keyPath)
		}
	}

	deliveries := connectorDeliveries(t, h, tok)
	want := map[string]bool{}
	for _, spec := range specs {
		want[spec.name] = true
	}
	for _, got := range deliveries.Items {
		if !want[got.Connector] {
			continue
		}
		if got.Status != "delivered" || got.Reason != "native_delivered" || got.Fingerprint == "" {
			t.Fatalf("bad catalog connector receipt for %s: %+v", got.Connector, got)
		}
		delete(want, got.Connector)
	}
	if len(want) != 0 {
		t.Fatalf("missing delivered catalog connector receipts for %+v; got %s", want, deliveries.Raw)
	}
}

func servedNativeDeployCredential(t *testing.T, h *servedHarness, cn string) ([]byte, []byte) {
	t.Helper()
	keyDER, err := crypto.GeneratePKCS8(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate deploy key: %v", err)
	}
	defer secret.Wipe(keyDER)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	signer, err := crypto.NewLockedSignerFromPKCS8(crypto.ECDSAP256, keyDER)
	if err != nil {
		secret.Wipe(keyPEM)
		t.Fatalf("load deploy signer: %v", err)
	}
	defer signer.Destroy()
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: cn,
		DNSNames:   []string{cn},
	}, signer)
	if err != nil {
		secret.Wipe(keyPEM)
		t.Fatalf("create deploy CSR: %v", err)
	}
	certPEM, err := h.srv.IssueLeaf(t.Context(), csrDER, time.Hour)
	if err != nil {
		secret.Wipe(keyPEM)
		t.Fatalf("issue deploy leaf: %v", err)
	}
	return certPEM, keyPEM
}

func enqueueServedConnectorDeploy(t *testing.T, h *servedHarness, idemKey, connectorName string, dep connector.Deployment) {
	t.Helper()
	payload, err := connector.EncodeDeploy(connectorName, dep)
	if err != nil {
		t.Fatalf("encode connector deploy: %v", err)
	}
	ctx := context.Background()
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := h.srv.outbox.Enqueue(ctx, tx, orchestrator.Entry{
			TenantID:       h.tenant,
			Destination:    "connector.deploy",
			IdempotencyKey: idemKey,
			Payload:        payload,
		})
		return err
	}); err != nil {
		t.Fatalf("enqueue connector deploy: %v", err)
	}
}

func connectorDeliveries(t *testing.T, h *servedHarness, tok string) connectorDeliveryList {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/connectors/deliveries", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("list connector deliveries: status %d body %s", status, body)
	}
	var out connectorDeliveryList
	out.Raw = body
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode connector deliveries: %v (%s)", err, body)
	}
	return out
}
