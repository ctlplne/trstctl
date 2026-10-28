// SPDX-License-Identifier: BUSL-1.1
//go:build integration

package conformance

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/eventspec"
	"trstctl.com/trstctl/internal/orchestrator"
	eereconcile "trstctl.com/trstctl/internal/reconcile"
	"trstctl.com/trstctl/internal/reconcile/canon"
	"trstctl.com/trstctl/internal/reconcile/rounds"
	"trstctl.com/trstctl/internal/reconcile/witness"
	corestore "trstctl.com/trstctl/internal/store"
)

// The lab images, pinned: EJBCA 9.6.3 Community, step-ca 0.30.2 and
// PostgreSQL 16.15 for step-ca's database.
const (
	xrecEJBCAImage    = "keyfactor/ejbca-ce@sha256:ef574ed81c1e2bb335902f1097b09f9408fe32f2c3abbccfe80999d1c9b50164"
	xrecStepCAImage   = "smallstep/step-ca@sha256:a2b17872915c193259b75a5474c398326f41bd199f0842093e52cf4182bc8270"
	xrecPostgresImage = "postgres@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea"
)

// TestE2E_ExternalCALedgersRoundToWitness is A218's acceptance on the
// production assembly: an EJBCA CA and a step-ca CA each run in containers
// and issue certificates; the certificate inventory holds some of them; one
// scheduled round per CA compares the CA's ledger with the inventory scoped to
// that CA, and each witness names exactly the drift, both ways:
//
//   - a certificate the CA revoked that the inventory still holds as active
//     (attribute conflict);
//   - a certificate the CA issued that the inventory lacks (held by the CA);
//   - a certificate the inventory holds that the CA's ledger never recorded
//     (held by the inventory): one EJBCA issued while the CA's certificate
//     storage was off, one signed offline with step-ca's intermediate key.
//
// It pulls and starts containers, so it runs only when asked:
//
//	TRSTCTL_XREC_CA_PROOF=1 go test -tags integration ./internal/reconcile/conformance -run ExternalCALedgers -v
func TestE2E_ExternalCALedgersRoundToWitness(t *testing.T) {
	if os.Getenv("TRSTCTL_XREC_CA_PROOF") != "1" {
		t.Skip("set TRSTCTL_XREC_CA_PROOF=1 to run the EJBCA and step-ca container proof (needs Docker)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not installed")
	}
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	ejbca := startXRECEJBCA(t, suffix)
	stepca := startXRECStepCA(t, suffix)
	h := newE2EHarness(t)

	for _, der := range [][]byte{ejbca.issuer, ejbca.leaves["leafa"], ejbca.leaves["leafb"], ejbca.leaves["unstored"],
		stepca.leaves["leaf1"], stepca.leaves["leaf2"], stepca.leaves["offline"]} {
		if _, err := h.store.UpsertCertificate(h.ctx, corestore.Certificate{
			TenantID: h.tenant, Subject: "CN=lab", Fingerprint: crypto.SHA256Hex(der), CertificateDER: der, Source: "e2e-seed",
		}); err != nil {
			t.Fatalf("seed inventory: %v", err)
		}
	}

	plane := func(id string) rounds.PlaneConfig { return rounds.PlaneConfig{AuthorityID: id, Liveness: time.Hour} }
	rt, err := eereconcile.NewRuntime(eereconcile.RuntimeConfig{
		Store:       h.store,
		Log:         h.log,
		Idempotency: orchestrator.NewIdempotency(h.store),
		Signer:      e2eSignerProvider{client: h.client},
		Logger:      slog.New(slog.NewTextHandler(os.Stderr, nil)),
		Schedules: []rounds.Config{
			{TenantID: h.tenant, Cadence: 2 * time.Second, Liveness: time.Hour, Planes: []rounds.PlaneConfig{plane("inventory-ejbca"), plane("ejbca-lab")}},
			{TenantID: h.tenant, Cadence: 2 * time.Second, Liveness: time.Hour, Planes: []rounds.PlaneConfig{plane("inventory-stepca"), plane("stepca-lab")}},
		},
		RoundInterval: 200 * time.Millisecond,
		EJBCASources: []eereconcile.EJBCASourceConfig{{
			AuthorityID: "ejbca-lab", Address: ejbca.address, ServerName: "ejbca.lab.test", CAFile: ejbca.caFile,
			ClientCertFile: ejbca.clientCert, ClientKeyFile: ejbca.clientKey, IssuerCertificatesFile: ejbca.issuersFile,
			CANames: []string{"LabIssuingCA"}, AllowLoopback: true,
		}},
		StepCASources: []eereconcile.StepCASourceConfig{{
			AuthorityID: "stepca-lab", DSNFile: stepca.dsnFile, IssuerCertificatesFile: stepca.issuersFile, AllowLoopback: true,
		}},
		InventoryAuthorities: []eereconcile.InventoryAuthorityConfig{
			{AuthorityID: "inventory-ejbca", IssuerCertificatesFile: ejbca.issuersFile},
			{AuthorityID: "inventory-stepca", IssuerCertificatesFile: stepca.issuersFile},
		},
	})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	workerCtx, cancel := context.WithCancel(h.ctx)
	done := make(chan error, 1)
	go func() { done <- rt.BackgroundWorkers[0].Run(workerCtx) }()
	var byPair map[string]witness.WitnessRecorded
	deadline := time.Now().Add(5 * time.Minute)
	for {
		byPair = firstWitnessPerPair(t, h.log)
		if len(byPair) == 2 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("witnesses within 5 minutes: %d of the two pairs", len(byPair))
		}
		time.Sleep(500 * time.Millisecond)
	}
	cancel()
	<-done

	stable := func(der []byte) string {
		t.Helper()
		facts, err := crypto.CertificateFactsFromDER(der)
		if err != nil {
			t.Fatal(err)
		}
		id, err := canon.X509StableID(facts.IssuerNameDER, facts.SerialHex)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	type want struct{ class, holder string }
	for pair, expected := range map[string]map[string]want{
		"ejbca-lab|inventory-ejbca": {
			stable(ejbca.leaves["leafb"]):    {witness.ClassAttributeConflict, ""},
			stable(ejbca.leaves["leafc"]):    {witness.ClassPresence, "ejbca-lab"},
			stable(ejbca.leaves["unstored"]): {witness.ClassPresence, "inventory-ejbca"},
		},
		"inventory-stepca|stepca-lab": {
			stable(stepca.leaves["leaf2"]):   {witness.ClassAttributeConflict, ""},
			stable(stepca.leaves["leaf3"]):   {witness.ClassPresence, "stepca-lab"},
			stable(stepca.leaves["offline"]): {witness.ClassPresence, "inventory-stepca"},
		},
	} {
		recorded, ok := byPair[pair]
		if !ok {
			t.Fatalf("no witness for %s (have %v)", pair, byPair)
		}
		entries := recorded.Evidence.Body.Entries
		if len(entries) != len(expected) {
			t.Fatalf("%s witness entries = %+v; want exactly %d: the revocation conflict, the CA-only and the inventory-only certificate",
				pair, entries, len(expected))
		}
		for _, entry := range entries {
			w, ok := expected[entry.RecordKey.StableID]
			if !ok || entry.Class != w.class || (w.holder != "" && entry.PresentAuthority != w.holder) {
				t.Fatalf("%s entry %+v; want %+v", pair, entry, expected)
			}
		}
	}
}

// An inventory authority asserts only certificates of the CAs in its issuer
// file that are unexpired at the observation, active or revoked.
func TestE2E_InventoryAuthorityScopesToTheNamedCAs(t *testing.T) {
	h := newE2EHarness(t)
	newCA := func(cn string) (*crypto.LockedSigner, []byte) {
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		der, err := crypto.SelfSignedCACert(key, cn, 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return key, der
	}
	leaf := func(caKey *crypto.LockedSigner, caDER []byte, name string, ttl time.Duration) []byte {
		hostKey, err := crypto.GenerateHostSubjectKey(name, []string{name})
		if err != nil {
			t.Fatal(err)
		}
		der, err := crypto.SignLeafFromCSR(caDER, caKey, hostKey.CSRDER, ttl)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	labKey, labDER := newCA("inventory scope lab CA")
	otherKey, otherDER := newCA("inventory scope other CA")
	inScope := leaf(labKey, labDER, "in.scope.example", time.Hour)
	expired := leaf(labKey, labDER, "expired.scope.example", time.Second)
	foreign := leaf(otherKey, otherDER, "foreign.scope.example", time.Hour)
	for _, der := range [][]byte{inScope, expired, foreign} {
		if _, err := h.store.UpsertCertificate(h.ctx, corestore.Certificate{
			TenantID: h.tenant, Subject: "CN=scope", Fingerprint: crypto.SHA256Hex(der), CertificateDER: der, Source: "e2e-seed",
		}); err != nil {
			t.Fatal(err)
		}
	}
	issuers := filepath.Join(t.TempDir(), "issuers.pem")
	if err := os.WriteFile(issuers, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: labDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	rt, err := eereconcile.NewRuntime(eereconcile.RuntimeConfig{
		Store:                h.store,
		InventoryAuthorities: []eereconcile.InventoryAuthorityConfig{{AuthorityID: "inventory-lab", IssuerCertificatesFile: issuers}},
	})
	if err != nil {
		t.Fatal(err)
	}
	obs, err := rt.Reducers.Observe(h.ctx, "inventory-lab", h.tenant)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	facts, err := crypto.CertificateFactsFromDER(inScope)
	if err != nil {
		t.Fatal(err)
	}
	want, err := canon.X509StableID(facts.IssuerNameDER, facts.SerialHex)
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.Set.Records) != 1 || obs.Set.Records[0].RecordKey.StableID != want || obs.Set.Records[0].Status != canon.StatusActive {
		t.Fatalf("records = %+v; want only the unexpired certificate of the named CA", obs.Set.Records)
	}
}

// firstWitnessPerPair is the first recorded witness for each authority pair,
// keyed by the sorted authority ids.
func firstWitnessPerPair(t *testing.T, log interface {
	Replay(context.Context, uint64, func(eventspec.Event) error) error
}) map[string]witness.WitnessRecorded {
	t.Helper()
	out := map[string]witness.WitnessRecorded{}
	if err := log.Replay(context.Background(), 1, func(ev eventspec.Event) error {
		if ev.Type != witness.EventTypeWitnessRecorded {
			return nil
		}
		var recorded witness.WitnessRecorded
		decodeConformanceEvent(t, ev, &recorded)
		ids := append([]string(nil), recorded.Authorities...)
		sort.Strings(ids)
		key := strings.Join(ids, "|")
		if _, ok := out[key]; !ok {
			out[key] = recorded
		}
		return nil
	}); err != nil {
		t.Fatalf("replay: %v", err)
	}
	return out
}

func xrecDocker(t *testing.T, timeout time.Duration, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput() // #nosec G204 -- fixed docker subcommands with test-owned arguments (CWE-78)
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func xrecRemove(kind string, names ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	args := append([]string{kind, "rm", "-f"}, names...)
	if kind == "container" {
		args = append([]string{"rm", "-f"}, names...)
	}
	_ = exec.CommandContext(ctx, "docker", args...).Run() // #nosec G204 -- fixed docker cleanup of test-owned resources (CWE-78)
}

func xrecPEMCert(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- a certificate this test copied out of its own container (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("%s holds no certificate", path)
	}
	return block.Bytes
}

func xrecHostPort(t *testing.T, container, port string) string {
	t.Helper()
	out := strings.TrimSpace(xrecDocker(t, time.Minute, "port", container, port))
	if i := strings.Index(out, "\n"); i >= 0 {
		out = out[:i]
	}
	return out
}

type xrecEJBCALab struct {
	address, caFile, clientCert, clientKey, issuersFile string
	issuer                                              []byte
	leaves                                              map[string][]byte
}

// startXRECEJBCA starts EJBCA, enables the REST certificate APIs, creates a
// lab issuing CA, a REST administrator's client certificate in the Super
// Administrator role, and the lab leaves: leafA and leafB (revoked) and leafC
// stored, and "unstored" issued while the CA's certificate storage was off.
func startXRECEJBCA(t *testing.T, suffix string) xrecEJBCALab {
	t.Helper()
	name := "trstctl-xrec-ejbca-" + suffix
	xrecDocker(t, 10*time.Minute, "run", "-d", "--name", name, "-h", "ejbca.lab.test", "-p", "127.0.0.1::8443",
		"-e", "TLS_SETUP_ENABLED=true", xrecEJBCAImage)
	t.Cleanup(func() { xrecRemove("container", name) })
	deadline := time.Now().Add(8 * time.Minute)
	for {
		out, err := exec.Command("docker", "exec", name, "/opt/keyfactor/bin/ejbca.sh", "ca", "listcas").CombinedOutput() // #nosec G204 -- fixed docker probe of the test's own container (CWE-78)
		if err == nil && strings.Contains(string(out), "ManagementCA") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("EJBCA did not create its ManagementCA within 8 minutes:\n%s", out)
		}
		time.Sleep(5 * time.Second)
	}
	cli := func(args ...string) {
		t.Helper()
		xrecDocker(t, 3*time.Minute, append([]string{"exec", name, "/opt/keyfactor/bin/ejbca.sh"}, args...)...)
	}
	enrollment := "xrec-enroll-" + suffix
	endEntity := func(user, cn, caName, profile, altName string) {
		t.Helper()
		args := []string{"ra", "addendentity", "--username", user, "--dn", "CN=" + cn, "--caname", caName, "--type", "1",
			"--token", "PEM", "--password", enrollment, "--certprofile", profile, "--eeprofile", "EMPTY"}
		if altName != "" {
			args = append(args, "--altname", altName)
		}
		cli(args...)
		cli("ra", "setclearpwd", user, enrollment)
		cli("batch", user, "-dir", "/tmp/xrec")
	}
	cli("config", "protocols", "enable", "--name", "REST Certificate Management")
	cli("config", "protocols", "enable", "--name", "REST Certificate Management V2")
	cli("ca", "init", "--caname", "LabIssuingCA", "--dn", "CN=trstctl lab issuing CA,O=trstctl lab", "--tokenType", "soft",
		"--tokenPass", "null", "--keytype", "ECDSA", "--keyspec", "prime256v1", "-v", "3650", "--policy", "null", "-s", "SHA256WithECDSA")
	xrecDocker(t, time.Minute, "exec", name, "mkdir", "-p", "/tmp/xrec")
	cli("ca", "getcacert", "--caname", "LabIssuingCA", "-f", "/tmp/xrec/labca.pem")
	endEntity("restadmin", "restadmin", "ManagementCA", "ENDUSER", "")
	cli("roles", "addrolemember", "--role", "Super Administrator Role", "--caname", "ManagementCA",
		"--with", "CertificateAuthenticationToken:WITH_COMMONNAME", "--value", "restadmin")
	for _, leaf := range []string{"leafa", "leafb", "leafc"} {
		endEntity(leaf, leaf+".ejbca.lab.test", "LabIssuingCA", "SERVER", "dNSName="+leaf+".ejbca.lab.test")
	}
	cli("ca", "editca", "--caname", "LabIssuingCA", "--field", "useCertificateStorage", "--value", "false")
	endEntity("unstored", "unstored.ejbca.lab.test", "LabIssuingCA", "SERVER", "dNSName=unstored.ejbca.lab.test")
	cli("ca", "editca", "--caname", "LabIssuingCA", "--field", "useCertificateStorage", "--value", "true")
	cli("ra", "revokeendentity", "--username", "leafb", "-r", "1")

	dir := t.TempDir()
	xrecDocker(t, time.Minute, "cp", name+":/tmp/xrec/.", dir)
	lab := xrecEJBCALab{
		address:     "https://" + xrecHostPort(t, name, "8443/tcp"),
		caFile:      filepath.Join(dir, "pem", "restadmin-CA.pem"),
		clientCert:  filepath.Join(dir, "pem", "restadmin.pem"),
		clientKey:   filepath.Join(dir, "pem", "restadmin-Key.pem"),
		issuersFile: filepath.Join(dir, "labca.pem"),
		leaves:      map[string][]byte{},
	}
	lab.issuer = xrecPEMCert(t, lab.issuersFile)
	for _, leaf := range []string{"leafa", "leafb", "leafc", "unstored"} {
		lab.leaves[leaf] = xrecPEMCert(t, filepath.Join(dir, "pem", leaf+".ejbca.lab.test.pem"))
	}
	return lab
}

type xrecStepCALab struct {
	dsnFile, issuersFile string
	leaves               map[string][]byte
}

// startXRECStepCA starts step-ca on a PostgreSQL database and issues leaf1,
// leaf2 (revoked) and leaf3 through the CA, plus "offline", signed with the
// intermediate key outside step-ca, so its database never records it.
func startXRECStepCA(t *testing.T, suffix string) xrecStepCALab {
	t.Helper()
	network, pg, ca, volume := "trstctl-xrec-net-"+suffix, "trstctl-xrec-pg-"+suffix, "trstctl-xrec-stepca-"+suffix, "trstctl-xrec-stepca-"+suffix
	dbPassword := "xrec-" + suffix
	xrecDocker(t, time.Minute, "network", "create", network)
	t.Cleanup(func() { xrecRemove("network", network) })
	xrecDocker(t, time.Minute, "volume", "create", volume)
	t.Cleanup(func() { xrecRemove("volume", volume) })
	xrecDocker(t, 5*time.Minute, "run", "-d", "--name", pg, "--network", network, "-p", "127.0.0.1::5432",
		"-e", "POSTGRES_USER=stepca", "-e", "POSTGRES_PASSWORD="+dbPassword, "-e", "POSTGRES_DB=stepca", xrecPostgresImage)
	t.Cleanup(func() { xrecRemove("container", pg) })
	xrecDocker(t, 5*time.Minute, "run", "--rm", "-v", volume+":/home/step", "-e", "LAB_PASSWORD=xrec-ca-"+suffix,
		"--entrypoint", "/bin/bash", xrecStepCAImage, "-c",
		`set -e; export STEPPATH=/home/step; echo "$LAB_PASSWORD" > /home/step/password
step ca init --name "trstctl lab step-ca" --dns "localhost,stepca.lab.test" --provisioner admin --password-file /home/step/password --provisioner-password-file /home/step/password --address :9000 >/dev/null
cp /home/step/password /home/step/secrets/password`)
	// Point step-ca's database at PostgreSQL.
	dir := t.TempDir()
	tmp := ca + "-config"
	xrecDocker(t, time.Minute, "create", "--name", tmp, "-v", volume+":/home/step", xrecStepCAImage)
	xrecDocker(t, time.Minute, "cp", tmp+":/home/step/config/ca.json", filepath.Join(dir, "ca.json"))
	raw, err := os.ReadFile(filepath.Join(dir, "ca.json")) // #nosec G304 -- the test's own copied config (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(raw, &config); err != nil {
		t.Fatal(err)
	}
	config["db"] = map[string]any{"type": "postgresql", "database": "stepca",
		"dataSource": "postgresql://stepca:" + dbPassword + "@" + pg + ":5432/?sslmode=disable"}
	raw, err = json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.json"), raw, 0o644); err != nil { // #nosec G306 -- step-ca's lab config, read by the container's user (CWE-276)
		t.Fatal(err)
	}
	xrecDocker(t, time.Minute, "cp", filepath.Join(dir, "ca.json"), tmp+":/home/step/config/ca.json")
	xrecRemove("container", tmp)
	xrecDocker(t, 5*time.Minute, "run", "-d", "--name", ca, "--network", network, "-v", volume+":/home/step", xrecStepCAImage)
	t.Cleanup(func() { xrecRemove("container", ca) })
	deadline := time.Now().Add(2 * time.Minute)
	for {
		out, err := exec.Command("docker", "exec", ca, "step", "ca", "health").CombinedOutput() // #nosec G204 -- fixed docker probe of the test's own container (CWE-78)
		if err == nil && strings.Contains(string(out), "ok") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("step-ca did not become healthy:\n%s\n%s", out, xrecDocker(t, time.Minute, "logs", ca))
		}
		time.Sleep(2 * time.Second)
	}
	step := func(args ...string) {
		t.Helper()
		xrecDocker(t, 2*time.Minute, append([]string{"exec", ca, "step"}, args...)...)
	}
	for _, leaf := range []string{"leaf1", "leaf2", "leaf3"} {
		step("ca", "certificate", leaf+".stepca.lab.test", "/tmp/"+leaf+".crt", "/tmp/"+leaf+".key",
			"--provisioner", "admin", "--provisioner-password-file", "/home/step/secrets/password", "--force")
	}
	step("ca", "revoke", "--cert", "/tmp/leaf2.crt", "--key", "/tmp/leaf2.key", "--reason", "xrec lab")
	step("certificate", "create", "offline.stepca.lab.test", "/tmp/offline.crt", "/tmp/offline.key", "--profile", "leaf",
		"--ca", "/home/step/certs/intermediate_ca.crt", "--ca-key", "/home/step/secrets/intermediate_ca_key",
		"--ca-password-file", "/home/step/secrets/password", "--no-password", "--insecure", "--not-after", "24h")
	lab := xrecStepCALab{issuersFile: filepath.Join(dir, "intermediate_ca.crt"), dsnFile: filepath.Join(dir, "stepca.dsn"), leaves: map[string][]byte{}}
	xrecDocker(t, time.Minute, "cp", ca+":/home/step/certs/intermediate_ca.crt", lab.issuersFile)
	for _, leaf := range []string{"leaf1", "leaf2", "leaf3", "offline"} {
		path := filepath.Join(dir, leaf+".crt")
		xrecDocker(t, time.Minute, "cp", ca+":/tmp/"+leaf+".crt", path)
		lab.leaves[leaf] = xrecPEMCert(t, path)
	}
	dsn := "postgres://stepca:" + dbPassword + "@" + xrecHostPort(t, pg, "5432/tcp") + "/stepca?sslmode=disable"
	if err := os.WriteFile(lab.dsnFile, []byte(dsn), 0o600); err != nil {
		t.Fatal(err)
	}
	return lab
}
