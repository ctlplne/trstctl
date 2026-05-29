package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"certctl.io/certctl/internal/api/problem"
	"certctl.io/certctl/internal/orchestrator"
	"certctl.io/certctl/internal/store"
)

const specPath = "/api/v1/openapi.json"

// API is the REST surface. It holds the read store, the idempotency recorder
// (AN-5), and the lifecycle orchestrator, and resolves the tenant per request.
type API struct {
	store    *store.Store
	idem     *orchestrator.Idempotency
	orch     *orchestrator.Orchestrator
	tenantFn func(*http.Request) (string, error)
	mux      *http.ServeMux
	spec     *Document
}

// New builds the API over its dependencies and wires the routes. The static
// OpenAPI document is built once from the route registry. The dependencies may
// be nil when only the spec is needed (e.g. for documentation tooling).
func New(st *store.Store, idem *orchestrator.Idempotency, orch *orchestrator.Orchestrator) *API {
	a := &API{store: st, idem: idem, orch: orch, tenantFn: tenantFromHeader}
	mux := http.NewServeMux()
	for _, r := range a.routes() {
		mux.HandleFunc(r.method+" "+r.path, r.handler)
	}
	mux.HandleFunc("/", a.notFound)
	a.mux = mux
	a.spec = buildSpec(a.routes())
	return a
}

// ServeHTTP implements http.Handler.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) { a.mux.ServeHTTP(w, r) }

// Route is a served (method, path) pair, exposed so documentation tooling and
// tests can confirm the spec covers every route.
type Route struct {
	Method string
	Path   string
}

// Routes returns the served routes.
func (a *API) Routes() []Route {
	rs := a.routes()
	out := make([]Route, 0, len(rs))
	for _, r := range rs {
		out = append(out, Route{Method: r.method, Path: r.path})
	}
	return out
}

// param is an OpenAPI query parameter descriptor.
type param struct {
	name string
	typ  string
	desc string
}

// route binds an HTTP method+path to a handler and carries the metadata used to
// generate the OpenAPI document.
type route struct {
	method      string
	path        string
	opID        string
	summary     string
	handler     http.HandlerFunc
	pathParams  []string
	query       []param
	reqSchema   string
	resSchema   string
	successCode string
	mutation    bool
}

func (a *API) routes() []route {
	page := []param{
		{name: "limit", typ: "integer", desc: "maximum items per page (1-100, default 20)"},
		{name: "cursor", typ: "string", desc: "opaque pagination cursor from a prior page"},
	}
	return []route{
		{method: "POST", path: "/api/v1/owners", opID: "createOwner", summary: "Create an owner", handler: a.createOwner, reqSchema: "OwnerRequest", resSchema: "Owner", successCode: "201", mutation: true},
		{method: "GET", path: "/api/v1/owners", opID: "listOwners", summary: "List owners", handler: a.listOwners, query: page, resSchema: "OwnerList", successCode: "200"},
		{method: "GET", path: "/api/v1/owners/{id}", opID: "getOwner", summary: "Get an owner", handler: a.getOwner, pathParams: []string{"id"}, resSchema: "Owner", successCode: "200"},
		{method: "PUT", path: "/api/v1/owners/{id}", opID: "updateOwner", summary: "Replace an owner", handler: a.updateOwner, pathParams: []string{"id"}, reqSchema: "OwnerRequest", resSchema: "Owner", successCode: "200", mutation: true},
		{method: "DELETE", path: "/api/v1/owners/{id}", opID: "deleteOwner", summary: "Delete an owner", handler: a.deleteOwner, pathParams: []string{"id"}, successCode: "204", mutation: true},

		{method: "POST", path: "/api/v1/issuers", opID: "createIssuer", summary: "Create an issuer", handler: a.createIssuer, reqSchema: "IssuerRequest", resSchema: "Issuer", successCode: "201", mutation: true},
		{method: "GET", path: "/api/v1/issuers", opID: "listIssuers", summary: "List issuers", handler: a.listIssuers, query: page, resSchema: "IssuerList", successCode: "200"},
		{method: "GET", path: "/api/v1/issuers/{id}", opID: "getIssuer", summary: "Get an issuer", handler: a.getIssuer, pathParams: []string{"id"}, resSchema: "Issuer", successCode: "200"},

		{method: "POST", path: "/api/v1/identities", opID: "createIdentity", summary: "Create an identity", handler: a.createIdentity, reqSchema: "IdentityRequest", resSchema: "Identity", successCode: "201", mutation: true},
		{method: "GET", path: "/api/v1/identities", opID: "listIdentities", summary: "List identities", handler: a.listIdentities, query: page, resSchema: "IdentityList", successCode: "200"},
		{method: "GET", path: "/api/v1/identities/{id}", opID: "getIdentity", summary: "Get an identity", handler: a.getIdentity, pathParams: []string{"id"}, resSchema: "Identity", successCode: "200"},
		{method: "POST", path: "/api/v1/identities/{id}/transitions", opID: "transitionIdentity", summary: "Apply a lifecycle transition", handler: a.transitionIdentity, pathParams: []string{"id"}, reqSchema: "TransitionRequest", resSchema: "Identity", successCode: "200", mutation: true},

		{method: "GET", path: specPath, opID: "getOpenAPISpec", summary: "OpenAPI 3.1 specification", handler: a.openapiHandler, successCode: "200"},
	}
}

// tenantFromHeader resolves the tenant from the X-Tenant-ID header. It is a
// placeholder for the auth-derived tenant (OIDC/mTLS/API token), which a later
// sprint substitutes via a custom resolver.
func tenantFromHeader(r *http.Request) (string, error) {
	t := r.Header.Get("X-Tenant-ID")
	if t == "" {
		return "", errors.New("missing X-Tenant-ID")
	}
	return t, nil
}

func (a *API) tenant(r *http.Request) (string, bool) {
	t, err := a.tenantFn(r)
	return t, err == nil
}

// cachedResponse is the response envelope stored by the idempotency recorder so
// a replayed key returns the identical status and body.
type cachedResponse struct {
	Status int             `json:"s"`
	Body   json.RawMessage `json:"b"`
}

// mutate runs a mutating operation under an idempotency key (AN-5): a replay
// returns the original response without re-executing. It requires a tenant and a
// non-empty key, both surfaced as problem+json.
func (a *API) mutate(w http.ResponseWriter, r *http.Request, idempotencyKey string, fn func(ctx context.Context, tenantID string) (int, any, error)) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problem.New(http.StatusUnauthorized, "missing or invalid tenant"))
		return
	}
	if idempotencyKey == "" {
		a.writeProblem(w, problem.New(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}

	raw, err := a.idem.Do(r.Context(), tenantID, idempotencyKey, func(ctx context.Context) ([]byte, error) {
		status, body, ferr := fn(ctx, tenantID)
		if ferr != nil {
			return nil, ferr
		}
		bodyJSON := json.RawMessage("null")
		if body != nil {
			bj, mErr := json.Marshal(body)
			if mErr != nil {
				return nil, mErr
			}
			bodyJSON = bj
		}
		return json.Marshal(cachedResponse{Status: status, Body: bodyJSON})
	})
	if err != nil {
		a.writeError(w, err)
		return
	}

	var c cachedResponse
	if err := json.Unmarshal(raw, &c); err != nil {
		a.writeError(w, err)
		return
	}
	if c.Status == http.StatusNoContent {
		w.WriteHeader(c.Status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c.Status)
	_, _ = w.Write(c.Body)
}

// apiError lets a handler choose the problem status for a domain failure.
type apiError struct {
	status int
	detail string
	ext    map[string]any
}

func (e *apiError) Error() string { return e.detail }

func errStatus(status int, detail string) *apiError { return &apiError{status: status, detail: detail} }

// writeError maps an error to a problem+json response.
func (a *API) writeError(w http.ResponseWriter, err error) {
	var ae *apiError
	switch {
	case errors.As(err, &ae):
		p := problem.New(ae.status, ae.detail)
		for k, v := range ae.ext {
			p = p.WithExtension(k, v)
		}
		a.writeProblem(w, p)
	case store.IsNotFound(err):
		a.writeProblem(w, problem.New(http.StatusNotFound, "resource not found"))
	case errors.Is(err, orchestrator.ErrInvalidTransition):
		p := problem.New(http.StatusConflict, err.Error())
		var te *orchestrator.TransitionError
		if errors.As(err, &te) {
			p = p.WithExtension("from", string(te.From)).WithExtension("to", string(te.To))
		}
		a.writeProblem(w, p)
	default:
		a.writeProblem(w, problem.New(http.StatusInternalServerError, "internal error"))
	}
}

func (a *API) writeProblem(w http.ResponseWriter, p *problem.Problem) { _ = p.Write(w) }

func problemUnauthorized() *problem.Problem {
	return problem.New(http.StatusUnauthorized, "missing or invalid tenant")
}

func (a *API) writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		a.writeProblem(w, problem.New(http.StatusInternalServerError, "failed to encode response"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func (a *API) notFound(w http.ResponseWriter, _ *http.Request) {
	a.writeProblem(w, problem.New(http.StatusNotFound, "no such resource"))
}

func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return errors.New("request body is required")
	}
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

// pageParams parses cursor-pagination query parameters, returning the page size
// and the keyset start id.
func (a *API) pageParams(r *http.Request) (limit int, after string, err error) {
	limit = 20
	if s := r.URL.Query().Get("limit"); s != "" {
		n, e := strconv.Atoi(s)
		if e != nil || n < 1 || n > 100 {
			return 0, "", errors.New("limit must be an integer between 1 and 100")
		}
		limit = n
	}
	after = store.ZeroUUID
	if c := r.URL.Query().Get("cursor"); c != "" {
		id, e := decodeCursor(c)
		if e != nil {
			return 0, "", errors.New("invalid cursor")
		}
		after = id
	}
	return limit, after, nil
}

func encodeCursor(id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(id))
}

func decodeCursor(c string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return "", err
	}
	if len(b) != 36 { // a UUID in canonical text form
		return "", errors.New("cursor is not a valid id")
	}
	return string(b), nil
}
