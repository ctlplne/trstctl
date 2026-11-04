// SPDX-License-Identifier: BUSL-1.1

package evaluate

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/protocols/spiffe/workloadpb"
)

// labWorkloadAPI is a Workload API socket as far as the workload journey uses
// it, signing real SVIDs through the crypto boundary.
type labWorkloadAPI struct {
	workloadpb.UnimplementedSpiffeWorkloadAPIServer
	id       string
	caDER    []byte
	ca       *crypto.LockedSigner
	jwt      *crypto.LockedSigner
	jwks     []byte
	wrongKey bool // hand over a key that is not the SVID's
	anyAud   bool // validate a token for any audience
}

func newLabWorkloadAPI(t *testing.T) *labWorkloadAPI {
	t.Helper()
	ca, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Destroy)
	caDER, err := crypto.SelfSignedCACert(ca, "lab trust domain", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	jwtKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(jwtKey.Destroy)
	jwk, err := crypto.PublicJWK(jwtKey.Public(), "lab-jwt")
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(crypto.JWKS{Keys: []crypto.JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	return &labWorkloadAPI{id: "spiffe://lab.test/payments", caDER: caDER, ca: ca, jwt: jwtKey, jwks: jwks}
}

func headerSent(ctx context.Context) error {
	if md, _ := metadata.FromIncomingContext(ctx); !slices.Equal(md.Get("workload.spiffe.io"), []string{"true"}) {
		return errors.New("no workload.spiffe.io header")
	}
	return nil
}

func (l *labWorkloadAPI) FetchX509SVID(_ *workloadpb.X509SVIDRequest, stream workloadpb.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	if err := headerSent(stream.Context()); err != nil {
		return err
	}
	leaf, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return err
	}
	defer leaf.Destroy()
	svid, err := crypto.SignSVID(l.caDER, l.ca, leaf.Public().DER, l.id, 10*time.Minute)
	if err != nil {
		return err
	}
	handed := leaf
	if l.wrongKey {
		other, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			return err
		}
		defer other.Destroy()
		handed = other
	}
	key, err := handed.PKCS8()
	if err != nil {
		return err
	}
	return stream.Send(&workloadpb.X509SVIDResponse{Svids: []*workloadpb.X509SVID{{SpiffeId: l.id, X509Svid: svid, X509SvidKey: key, Bundle: l.caDER}}})
}

func (l *labWorkloadAPI) FetchJWTSVID(ctx context.Context, req *workloadpb.JWTSVIDRequest) (*workloadpb.JWTSVIDResponse, error) {
	if err := headerSent(ctx); err != nil {
		return nil, err
	}
	token, err := crypto.SignJWT(l.jwt, "lab-jwt", map[string]any{"sub": l.id, "aud": req.GetAudience(), "exp": time.Now().Add(5 * time.Minute).Unix()})
	if err != nil {
		return nil, err
	}
	return &workloadpb.JWTSVIDResponse{Svids: []*workloadpb.JWTSVID{{SpiffeId: l.id, Svid: token}}}, nil
}

func (l *labWorkloadAPI) FetchJWTBundles(_ *workloadpb.JWTBundlesRequest, stream workloadpb.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	if err := headerSent(stream.Context()); err != nil {
		return err
	}
	return stream.Send(&workloadpb.JWTBundlesResponse{Bundles: map[string][]byte{"lab.test": l.jwks}})
}

func (l *labWorkloadAPI) ValidateJWTSVID(ctx context.Context, req *workloadpb.ValidateJWTSVIDRequest) (*workloadpb.ValidateJWTSVIDResponse, error) {
	if err := headerSent(ctx); err != nil {
		return nil, err
	}
	keys, err := crypto.ParseJWKS(l.jwks)
	if err != nil {
		return nil, err
	}
	raw, err := crypto.VerifyJWT(req.GetSvid(), keys)
	if err != nil {
		return nil, err
	}
	var claims struct {
		Sub string   `json:"sub"`
		Aud []string `json:"aud"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, err
	}
	if !l.anyAud && !slices.Contains(claims.Aud, req.GetAudience()) {
		return nil, errors.New("audience mismatch")
	}
	return &workloadpb.ValidateJWTSVIDResponse{SpiffeId: claims.Sub}, nil
}

// serveWorkloadAPI serves api on a socket short enough for every platform's
// limit and returns its path.
func serveWorkloadAPI(t *testing.T, api *labWorkloadAPI) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ev-wl-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "w.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	workloadpb.RegisterSpiffeWorkloadAPIServer(server, api)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	return socket
}

func workloadOptions(socket string) Options {
	return Options{Server: "https://cp.lab.test", Token: "lab-token", Journeys: []string{JourneyWorkload}, WorkloadSocket: socket, Timeout: 5 * time.Second}
}

// A249: the workload journey passes against a Workload API that hands over a
// verifiable SVID and token and refuses the token for another audience; a
// forced failure is reported as one; a socket that validates any audience or
// hands over the wrong key fails it.
func TestWorkloadJourneyA249(t *testing.T) {
	api := newLabWorkloadAPI(t)
	socket := serveWorkloadAPI(t, api)

	pack, err := Evaluate(t.Context(), workloadOptions(socket))
	if err != nil {
		t.Fatal(err)
	}
	if pack.Format != PackFormatV2 || pack.Verdict != StatusPass || len(pack.Journeys) != 1 {
		t.Fatalf("pack %s verdict %s, %d journeys: %+v", pack.Format, pack.Verdict, len(pack.Journeys), pack.Journeys)
	}
	got := pack.Journeys[0]
	if steps := stepStatuses(got.Steps); steps != "workload_x509=pass workload_jwt=pass workload_validate=pass" {
		t.Fatalf("workload journey: %s\n%+v", steps, got.Steps)
	}
	if got.Steps[0].Evidence["spiffe_id"] != api.id || !strings.HasPrefix(got.Steps[1].Evidence["token_sha256"], "sha256:") {
		t.Fatalf("evidence = %v / %v", got.Steps[0].Evidence, got.Steps[1].Evidence)
	}
	raw, err := json.Marshal(pack)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "eyJ") || strings.Contains(string(raw), "PRIVATE") {
		t.Fatalf("the pack carries a token or a key: %s", raw)
	}

	opts := workloadOptions(socket)
	opts.ForceFailure = JourneyWorkload
	forced, err := Evaluate(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if steps := stepStatuses(forced.Journeys[0].Steps); forced.Verdict != StatusFail || steps != "workload_x509=pass workload_jwt=pass workload_validate=fail" || !forced.Journeys[0].ForcedFailure {
		t.Fatalf("forced: verdict %s, %s", forced.Verdict, steps)
	}

	for _, tc := range []struct {
		name  string
		bend  func(*labWorkloadAPI)
		steps string
	}{
		{"a socket that validates any audience", func(l *labWorkloadAPI) { l.anyAud = true }, "workload_x509=pass workload_jwt=pass workload_validate=fail"},
		{"a socket that hands over another key", func(l *labWorkloadAPI) { l.wrongKey = true }, "workload_x509=fail workload_jwt=skipped workload_validate=skipped"},
	} {
		bent := newLabWorkloadAPI(t)
		tc.bend(bent)
		pack, err := Evaluate(t.Context(), workloadOptions(serveWorkloadAPI(t, bent)))
		if err != nil {
			t.Fatal(err)
		}
		if steps := stepStatuses(pack.Journeys[0].Steps); pack.Verdict != StatusFail || steps != tc.steps {
			t.Fatalf("%s: verdict %s, %s", tc.name, pack.Verdict, steps)
		}
	}

	none := workloadOptions("")
	if pack, err := Evaluate(t.Context(), none); err != nil || pack.Verdict != StatusFail ||
		!strings.Contains(pack.Journeys[0].Steps[0].Detail, "--workload-socket") {
		t.Fatalf("no socket = %v, %+v", err, pack.Journeys)
	}
}
