package server

import (
	"bytes"
	"context"
	"encoding/base64"
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
	"trstctl.com/trstctl/internal/connector/example"
	"trstctl.com/trstctl/internal/connector/javakeystore"
	"trstctl.com/trstctl/internal/connector/kemp"
	"trstctl.com/trstctl/internal/connector/kemp/kemptest"
	"trstctl.com/trstctl/internal/connector/mysql"
	"trstctl.com/trstctl/internal/connector/nginx"
	"trstctl.com/trstctl/internal/connector/postgresql"
	"trstctl.com/trstctl/internal/connector/rabbitmq"
	"trstctl.com/trstctl/internal/connector/tomcat"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
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

func TestServedConnectorDeployOutboxSealsPrivateKeyBeforeDispatch(t *testing.T) {
	ops := connector.NewMemoryOps()
	reg := connector.NewRegistry(func(string) connector.Ops { return ops })
	reg.Register(example.New("/deploy", "reload-service"))

	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ConnectorRegistry = reg
	})
	ctx := context.Background()

	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, "service", "sealed-outbox-owner", "")
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	attrs, err := json.Marshal(map[string]any{
		"connector": "filereload",
		"target":    "/deploy",
	})
	if err != nil {
		t.Fatal(err)
	}
	ident, err := h.srv.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind:       store.KindX509Certificate,
		Name:       "sealed-outbox.served.test",
		OwnerID:    owner.ID,
		Attributes: attrs,
	})
	if err != nil {
		t.Fatalf("create identity: %v", err)
	}
	if err := h.srv.orch.Transition(ctx, h.tenant, ident.ID, orchestrator.StateIssued, "issue connector-backed identity"); err != nil {
		t.Fatalf("transition to issued: %v", err)
	}

	if n, err := h.srv.outbox.Dispatch(ctx, h.srv.obHandler); err != nil || n != 1 {
		t.Fatalf("dispatch ca.issue = (%d, %v), want (1, nil)", n, err)
	}
	row := pendingServedOutboxByDestination(t, h, "connector.deploy")
	if bytes.Contains(row.Payload, []byte("PRIVATE KEY")) {
		t.Fatalf("connector.deploy outbox payload contains PEM marker: %q", row.Payload)
	}

	if n, err := h.srv.outbox.Dispatch(ctx, h.srv.obHandler); err != nil || n != 1 {
		t.Fatalf("dispatch connector.deploy = (%d, %v), want (1, nil)", n, err)
	}
	keyPEM, ok := ops.File("/deploy/tls.key")
	if !ok || !bytes.Contains(keyPEM, []byte("BEGIN PRIVATE KEY")) {
		t.Fatalf("connector did not receive the private key after sealed dispatch")
	}
	var decoded connector.DeployPayload
	if err := json.Unmarshal(row.Payload, &decoded); err == nil && bytes.Equal(decoded.KeyPEM, keyPEM) {
		t.Fatal("connector.deploy outbox payload is a reversible plaintext DeployPayload carrying the private key")
	}
	if bytes.Contains(row.Payload, keyPEM) {
		t.Fatal("connector.deploy outbox payload contains the exact private key PEM bytes")
	}
	if bytes.Contains(row.Payload, []byte(base64.StdEncoding.EncodeToString(keyPEM))) {
		t.Fatal("connector.deploy outbox payload contains a base64 copy of the private key PEM")
	}
}

func TestConnectorDeployPayloadSealerHidesKeyAndBindsAAD(t *testing.T) {
	kek, err := seal.NewLocalKEK(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatalf("NewLocalKEK: %v", err)
	}
	t.Cleanup(kek.Destroy)

	keyPEM := []byte("-----BEGIN PRIVATE KEY-----\nunit-test-key\n-----END PRIVATE KEY-----\n")
	payload, err := connector.EncodeIdentityDeploy("filereload", "identity-1", connector.Deployment{
		Target:      "/deploy",
		CertPEM:     []byte("cert"),
		KeyPEM:      keyPEM,
		Fingerprint: "fingerprint-1",
	})
	if err != nil {
		t.Fatalf("encode connector deploy: %v", err)
	}
	handler := &issuanceDispatcher{connectorPayloadKey: kek}
	sealedPayload, err := handler.sealConnectorDeployBytes("tenant-1", "connector.deploy", "deploy-1", payload)
	if err != nil {
		t.Fatalf("seal connector deploy: %v", err)
	}
	if bytes.Contains(sealedPayload, []byte("PRIVATE KEY")) || bytes.Contains(sealedPayload, keyPEM) {
		t.Fatalf("sealed payload leaked key material: %q", sealedPayload)
	}
	if bytes.Contains(sealedPayload, []byte(base64.StdEncoding.EncodeToString(keyPEM))) {
		t.Fatal("sealed payload contains a base64 copy of the private key")
	}
	var decoded connector.DeployPayload
	if err := json.Unmarshal(sealedPayload, &decoded); err == nil && bytes.Equal(decoded.KeyPEM, keyPEM) {
		t.Fatal("sealed payload still decodes as a plaintext connector deploy body")
	}

	msg := orchestrator.Message{
		TenantID:       "tenant-1",
		Destination:    "connector.deploy",
		IdempotencyKey: "deploy-1",
		Payload:        sealedPayload,
	}
	got, identityID, detail, err := handler.resolveDeployPayload(context.Background(), msg)
	if err != nil {
		t.Fatalf("open sealed connector deploy: %v", err)
	}
	defer secret.Wipe(got.KeyPEM)
	if identityID == nil || *identityID != "identity-1" || detail != "sealed connector deploy payload" {
		t.Fatalf("sealed metadata identity=%v detail=%q", identityID, detail)
	}
	if !bytes.Equal(got.KeyPEM, keyPEM) || got.Fingerprint != "fingerprint-1" {
		t.Fatal("sealed connector deploy did not round-trip credential material")
	}

	msg.IdempotencyKey = "deploy-2"
	if _, _, _, err := handler.resolveDeployPayload(context.Background(), msg); err == nil {
		t.Fatal("sealed connector deploy opened with the wrong idempotency-key AAD")
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

func TestServedEndpointBindingPushesCredentialsCAPLIFE05(t *testing.T) {
	const (
		nginxCertPath = "/etc/nginx/tls/fullchain.pem"
		nginxKeyPath  = "/etc/nginx/tls/privkey.pem"
		javaStorePath = "/opt/payments/tls/payments.p12"
		kempToken     = "cap-life-05-kemp-token"
		kempVS        = "vs-cap-life-05-443"
	)

	nginxOps := connector.NewMemoryOps()
	javaOps := connector.NewMemoryOps()
	kempSrv := kemptest.New(kempToken)
	defer kempSrv.Close()

	reg := connector.NewRegistry(func(name string) connector.Ops {
		switch name {
		case "nginx":
			return nginxOps
		case "java-keystore":
			return javaOps
		case "kemp":
			return connector.NewHTTPOps(kempSrv.Client())
		default:
			return nil
		}
	})
	reg.Register(nginx.New(nginxCertPath, nginxKeyPath))
	reg.Register(javakeystore.New(javaStorePath, "changeit", "payments"))
	reg.Register(kemp.New(kempSrv.URL(), []byte(kempToken)))

	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ConnectorRegistry = reg
	})
	tok := seedScopedToken(t, h.store, h.tenant, "owners:write", "connectors:read", "connectors:write")

	status, body := secretsReq(t, h, http.MethodPost, "/api/v1/owners", tok, map[string]any{
		"kind": "workload",
		"name": "cap-life-05-owner",
	})
	if status != http.StatusCreated {
		t.Fatalf("create owner: status %d body %s", status, body)
	}
	var owner struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &owner); err != nil {
		t.Fatalf("decode owner: %v", err)
	}

	for _, tc := range []struct {
		name      string
		connector string
		route     string
	}{
		{name: "cap-life-05-nginx.served.test", connector: "nginx", route: "edge/nginx/payments"},
		{name: "cap-life-05-java.served.test", connector: "java-keystore", route: "payments-keystore"},
		{name: "cap-life-05-kemp.served.test", connector: "kemp", route: kempVS},
	} {
		status, body = secretsReq(t, h, http.MethodPost, "/api/v1/lifecycle/endpoint-bindings", tok, map[string]any{
			"owner_id":      owner.ID,
			"identity_name": tc.name,
			"reason":        "cap-life-05 automated endpoint push",
			"target": map[string]any{
				"name":      "cap-life-05/" + tc.connector + "/" + tc.name,
				"connector": tc.connector,
				"config": map[string]any{
					"target":         tc.route,
					"credential_ref": "secret://connectors/" + tc.connector + "/cap-life-05",
				},
			},
		})
		if status != http.StatusCreated {
			t.Fatalf("create %s endpoint binding: status %d body %s", tc.connector, status, body)
		}
	}
	if err := h.srv.Drain(t.Context()); err != nil {
		t.Fatalf("drain endpoint binding pushes: %v", err)
	}

	nginxCert, ok := nginxOps.File(nginxCertPath)
	if !ok || !bytes.Contains(nginxCert, []byte("BEGIN CERTIFICATE")) {
		t.Fatalf("nginx connector did not receive an issued certificate")
	}
	nginxKey, ok := nginxOps.File(nginxKeyPath)
	if !ok || !bytes.Contains(nginxKey, []byte("BEGIN PRIVATE KEY")) {
		t.Fatalf("nginx connector did not receive the private key")
	}
	javaStore, ok := javaOps.File(javaStorePath)
	if !ok || len(javaStore) == 0 {
		t.Fatalf("java-keystore connector did not write a keystore")
	}
	kempBinding, ok := kempSrv.Binding(kempVS)
	if !ok || len(kempBinding.Certificate) == 0 || len(kempBinding.PrivateKey) == 0 {
		t.Fatalf("Kemp connector did not bind the issued credential: %+v ok=%v", kempBinding, ok)
	}

	deliveries := connectorDeliveries(t, h, tok)
	delivered := map[string]bool{}
	for _, got := range deliveries.Items {
		if got.Status == "delivered" && got.Reason == "native_delivered" && got.Fingerprint != "" {
			delivered[got.Connector] = true
		}
	}
	for _, want := range []string{"nginx", "java-keystore", "kemp"} {
		if !delivered[want] {
			t.Fatalf("missing delivered CAP-LIFE-05 receipt for %s; got %s", want, deliveries.Raw)
		}
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
	handler, ok := h.srv.obHandler.(*issuanceDispatcher)
	if !ok {
		t.Fatal("served outbox handler is not the issuance dispatcher")
	}
	payload, err = handler.sealConnectorDeployBytes(h.tenant, "connector.deploy", idemKey, payload)
	if err != nil {
		t.Fatalf("seal connector deploy: %v", err)
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

func pendingServedOutboxByDestination(t *testing.T, h *servedHarness, dest string) orchestrator.Record {
	t.Helper()
	rows, err := h.srv.outbox.Pending(context.Background(), h.tenant)
	if err != nil {
		t.Fatalf("pending outbox: %v", err)
	}
	for _, row := range rows {
		if row.Destination == dest {
			return row
		}
	}
	t.Fatalf("no pending %s outbox row in %+v", dest, rows)
	return orchestrator.Record{}
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
