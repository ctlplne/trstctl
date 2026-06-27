package est

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// ProfileRoute binds one EST profile server to an optional PathID. Empty PathID
// is the legacy /.well-known/est route family; non-empty PathIDs mount under
// /.well-known/est/<PathID>. EnableMTLS also mounts the authenticated sibling
// /.well-known/est-mtls/<PathID> route family.
type ProfileRoute struct {
	PathID     string
	Server     *Server
	EnableMTLS bool
}

// Dispatcher dispatches EST requests to per-profile servers by PathID.
type Dispatcher struct {
	mux *http.ServeMux
}

// NewDispatcher builds a PathID dispatcher for one or more EST profile servers.
func NewDispatcher(routes []ProfileRoute) (*Dispatcher, error) {
	if len(routes) == 0 {
		return nil, errors.New("est: dispatcher requires at least one profile route")
	}
	d := &Dispatcher{mux: http.NewServeMux()}
	seen := map[string]bool{}
	for _, route := range routes {
		if route.Server == nil {
			return nil, errors.New("est: profile route requires a server")
		}
		pathID := strings.Trim(route.PathID, "/")
		key := "est:" + pathID
		if seen[key] {
			return nil, errors.New("est: duplicate profile PathID")
		}
		seen[key] = true
		base := "/.well-known/est"
		if pathID != "" {
			base += "/" + pathID
		}
		d.mount(base, route.Server, false)
		if route.EnableMTLS {
			if pathID == "" {
				return nil, errors.New("est: mTLS sibling route requires a non-empty PathID")
			}
			mtlsKey := "est-mtls:" + pathID
			if seen[mtlsKey] {
				return nil, errors.New("est: duplicate mTLS profile PathID")
			}
			seen[mtlsKey] = true
			d.mount("/.well-known/est-mtls/"+pathID, route.Server, true)
		}
	}
	return d, nil
}

// ServeHTTP implements http.Handler.
func (d *Dispatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mux.ServeHTTP(w, r)
}

func (d *Dispatcher) mount(base string, server *Server, mtls bool) {
	for _, route := range []struct {
		method string
		suffix string
	}{
		{http.MethodGet, "/cacerts"},
		{http.MethodPost, "/simpleenroll"},
		{http.MethodPost, "/simplereenroll"},
		{http.MethodGet, "/csrattrs"},
		{http.MethodPost, "/serverkeygen"},
	} {
		d.mux.HandleFunc(route.method+" "+base+route.suffix, dispatchToProfile(server, route.suffix, mtls))
	}
}

func dispatchToProfile(server *Server, suffix string, mtls bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		next := r.Clone(routeContext(r.Context(), mtls))
		u := *r.URL
		u.Path = "/.well-known/est" + suffix
		u.RawPath = ""
		if _, err := url.Parse(u.String()); err != nil {
			http.Error(w, "bad EST route", http.StatusBadRequest)
			return
		}
		next.URL = &u
		server.ServeHTTP(w, next)
	}
}

func routeContext(ctx context.Context, mtls bool) context.Context {
	if !mtls {
		return ctx
	}
	return context.WithValue(ctx, mtlsRouteKey{}, true)
}

type mtlsRouteKey struct{}

func isMTLSRoute(ctx context.Context) bool {
	v, _ := ctx.Value(mtlsRouteKey{}).(bool)
	return v
}
