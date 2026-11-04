// SPDX-License-Identifier: BUSL-1.1

package evaluate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/protocols/spiffe"
	"trstctl.com/trstctl/internal/protocols/spiffe/workloadpb"
)

// The workload identity journey (A249). The evaluator is a workload on the
// host whose Workload API socket it is given — the control plane's own or a
// host agent's — and checks what it is handed the way a workload would: the
// X.509-SVID against the trust bundle, the JWT-SVID against the JWT bundle,
// and the socket's own validation, which must refuse the token for an
// audience it was not minted for.

// JourneyWorkload is the workload identity journey.
const JourneyWorkload = "workload"

// The workload journey's steps, in order.
const (
	StepWorkloadX509     = "workload_x509"
	StepWorkloadJWT      = "workload_jwt"
	StepWorkloadValidate = "workload_validate"
)

// workloadAPICall bounds one Workload API call; a stream's first message
// arrives within it or the step fails.
const workloadAPICall = 30 * time.Second

// dialWorkloadAPI connects to a Workload API socket. The socket is local and
// owner-scoped, so the transport's authentication is the kernel's (the server
// attests the caller's process), not TLS.
func dialWorkloadAPI(socket string) (*grpc.ClientConn, error) {
	path := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(socket), "unix://"), "unix:")
	if path == "" {
		return nil, errors.New("the workload journey needs --workload-socket, the Workload API socket a workload on this host uses")
	}
	return grpc.NewClient("unix://"+path, grpc.WithTransportCredentials(insecure.NewCredentials()))
}

// workloadCall is ctx bounded for one call, carrying the header every
// Workload API request must.
func workloadCall(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(ctx, workloadAPICall)
	return metadata.AppendToOutgoingContext(ctx, spiffe.SecurityHeaderKey, spiffe.SecurityHeaderValue), cancel
}

// trustDomainOf is a SPIFFE ID's trust domain.
func trustDomainOf(id string) string {
	return strings.SplitN(strings.TrimPrefix(id, "spiffe://"), "/", 2)[0]
}

func (j *journey) workloadJourney(ctx context.Context) JourneyResult {
	t := j.track(JourneyWorkload)
	limits := []string{
		"The workload journey runs where the Workload API socket is: it shows what a workload on this host is handed, not what other hosts' sockets serve.",
		"A JWT-SVID is revoked by its expiry; the journey does not revoke one.",
	}
	conn, err := dialWorkloadAPI(j.opts.WorkloadSocket)
	if err != nil {
		t.step(ctx, StepWorkloadX509, func(context.Context, *Step) error { return err })
		return t.finish(limits...)
	}
	defer func() { _ = conn.Close() }()
	client := workloadpb.NewSpiffeWorkloadAPIClient(conn)
	// An audience no other relying party uses, so the token this run is
	// handed is good for this run only.
	audience := "trstctl-evaluate-" + strings.TrimSuffix(j.keyPrefix, "-")
	var id string
	var token string

	t.step(ctx, StepWorkloadX509, func(ctx context.Context, s *Step) error {
		call, cancel := workloadCall(ctx)
		defer cancel()
		stream, err := client.FetchX509SVID(call, &workloadpb.X509SVIDRequest{})
		if err != nil {
			return fmt.Errorf("the Workload API refused an X.509-SVID: %w", err)
		}
		resp, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("the Workload API sent no X.509-SVID: %w", err)
		}
		// Every key handed over is wiped once it has been compared.
		defer func() {
			for _, svid := range resp.GetSvids() {
				secret.Wipe(svid.GetX509SvidKey())
			}
		}()
		if len(resp.GetSvids()) == 0 {
			return errors.New("the Workload API sent an empty X.509-SVID response")
		}
		svid := resp.GetSvids()[0]
		check, err := crypto.VerifyX509SVID(svid.GetX509Svid(), svid.GetBundle(), svid.GetX509SvidKey(), j.opts.Now())
		if err != nil {
			return err
		}
		if check.SPIFFEID != svid.GetSpiffeId() {
			return fmt.Errorf("the response names %s but its certificate carries %s", svid.GetSpiffeId(), check.SPIFFEID)
		}
		id = check.SPIFFEID
		s.Basis = BasisObserved
		s.Evidence["spiffe_id"] = id
		s.Evidence["not_after"] = check.NotAfter.UTC().Format(time.RFC3339)
		s.Detail = fmt.Sprintf("An X.509-SVID for %s chains to the trust bundle (%d %s), and the private key handed over is its own; it is valid until %s.",
			id, check.Authorities, plural(check.Authorities, "authority", "authorities"), check.NotAfter.UTC().Format(time.RFC3339))
		return nil
	})

	t.step(ctx, StepWorkloadJWT, func(ctx context.Context, s *Step) error {
		call, cancel := workloadCall(ctx)
		defer cancel()
		resp, err := client.FetchJWTSVID(call, &workloadpb.JWTSVIDRequest{Audience: []string{audience}, SpiffeId: id})
		if err != nil {
			return fmt.Errorf("the Workload API refused a JWT-SVID for %s: %w", audience, err)
		}
		if len(resp.GetSvids()) == 0 || resp.GetSvids()[0].GetSvid() == "" {
			return errors.New("the Workload API sent no JWT-SVID")
		}
		token = resp.GetSvids()[0].GetSvid()
		bundles, err := client.FetchJWTBundles(call, &workloadpb.JWTBundlesRequest{})
		if err != nil {
			return fmt.Errorf("the Workload API refused the JWT bundle: %w", err)
		}
		first, err := bundles.Recv()
		if err != nil {
			return fmt.Errorf("the Workload API sent no JWT bundle: %w", err)
		}
		raw, ok := first.GetBundles()[trustDomainOf(id)]
		if !ok {
			return fmt.Errorf("the JWT bundles name no key set for the trust domain %s", trustDomainOf(id))
		}
		keys, err := crypto.ParseJWKS(raw)
		if err != nil {
			return fmt.Errorf("the JWT bundle for %s: %w", trustDomainOf(id), err)
		}
		claimsJSON, err := crypto.VerifyJWT(token, keys)
		if err != nil {
			return fmt.Errorf("the JWT-SVID does not verify against its trust domain's JWT bundle: %w", err)
		}
		var claims struct {
			Sub string          `json:"sub"`
			Aud json.RawMessage `json:"aud"`
			Exp int64           `json:"exp"`
		}
		if err := json.Unmarshal(claimsJSON, &claims); err != nil {
			return fmt.Errorf("the JWT-SVID's claims do not parse: %w", err)
		}
		var audiences []string
		if err := json.Unmarshal(claims.Aud, &audiences); err != nil {
			var one string
			if json.Unmarshal(claims.Aud, &one) != nil {
				return errors.New("the JWT-SVID carries no audience")
			}
			audiences = []string{one}
		}
		expires := time.Unix(claims.Exp, 0).UTC()
		switch {
		case claims.Sub != id:
			return fmt.Errorf("the JWT-SVID's subject is %q, not %s", claims.Sub, id)
		case !slices.Contains(audiences, audience):
			return fmt.Errorf("the JWT-SVID's audience is %v, not %s", audiences, audience)
		case !expires.After(j.opts.Now()):
			return fmt.Errorf("the JWT-SVID expired at %s", expires.Format(time.RFC3339))
		}
		s.Basis = BasisObserved
		s.Evidence["audience"] = audience
		s.Evidence["token_sha256"] = digestOf(token)
		s.Detail = fmt.Sprintf("A JWT-SVID for %s, audience %s, verifies offline against the trust domain's JWT bundle; it expires at %s.",
			id, audience, expires.Format(time.RFC3339))
		return nil
	})

	t.step(ctx, StepWorkloadValidate, func(ctx context.Context, s *Step) error {
		call, cancel := workloadCall(ctx)
		defer cancel()
		valid, err := client.ValidateJWTSVID(call, &workloadpb.ValidateJWTSVIDRequest{Audience: audience, Svid: token})
		if err != nil {
			return fmt.Errorf("the Workload API did not validate its own token for %s: %w", audience, err)
		}
		if valid.GetSpiffeId() != id {
			return fmt.Errorf("the Workload API validated the token as %s, not %s", valid.GetSpiffeId(), id)
		}
		other := audience + "-elsewhere"
		_, err = client.ValidateJWTSVID(call, &workloadpb.ValidateJWTSVIDRequest{Audience: other, Svid: token})
		refused := err != nil
		if t.result.ForcedFailure {
			if refused {
				return fmt.Errorf("expected the token minted for %s to validate for %s, and the Workload API refused it", audience, other)
			}
			return fmt.Errorf("expected the token minted for %s to validate for %s; it did, and it should not have", audience, other)
		}
		if !refused {
			return fmt.Errorf("the Workload API validated a token minted for %s for another audience, %s", audience, other)
		}
		s.Basis = BasisObserved
		s.Detail = fmt.Sprintf("The Workload API validates the token for %s as %s and refuses it for %s.", audience, id, other)
		return nil
	})
	return t.finish(limits...)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
