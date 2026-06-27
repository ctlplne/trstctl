package scep

import (
	"fmt"
	"net/http"
	"strings"
)

// ProfileRoute binds one URL path segment under /scep to one SCEP server. A route
// with an empty PathID is the legacy root endpoint (/scep and /scep/pkiclient.exe).
type ProfileRoute struct {
	PathID string
	Server *Server
}

// Dispatcher serves multiple SCEP profiles from one HTTP mount. It preserves the
// legacy root route while allowing /scep/<pathID> and /scep/<pathID>/pkiclient.exe
// to carry profile-local RA material and enrollment policy.
type Dispatcher struct {
	root     *Server
	profiles map[string]*Server
}

// NewDispatcher builds a SCEP profile dispatcher.
func NewDispatcher(routes []ProfileRoute) (*Dispatcher, error) {
	d := &Dispatcher{profiles: make(map[string]*Server)}
	for _, route := range routes {
		if route.Server == nil {
			return nil, errorsForPath(route.PathID, "server is required")
		}
		if !validPathID(route.PathID) {
			return nil, errorsForPath(route.PathID, "path id must be lowercase [a-z0-9-] with no leading or trailing hyphen")
		}
		if route.PathID == "" {
			if d.root != nil {
				return nil, errorsForPath(route.PathID, "duplicate route")
			}
			d.root = route.Server
			continue
		}
		if _, exists := d.profiles[route.PathID]; exists {
			return nil, errorsForPath(route.PathID, "duplicate route")
		}
		d.profiles[route.PathID] = route.Server
	}
	return d, nil
}

// ServeHTTP implements http.Handler.
func (d *Dispatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pathID, rewritePath, ok := scepProfilePath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	var srv *Server
	if pathID == "" {
		srv = d.root
	} else {
		srv = d.profiles[pathID]
	}
	if srv == nil {
		http.NotFound(w, r)
		return
	}
	r2 := r.Clone(r.Context())
	u := *r.URL
	u.Path = rewritePath
	u.RawPath = ""
	r2.URL = &u
	srv.ServeHTTP(w, r2)
}

func scepProfilePath(path string) (pathID, rewritePath string, ok bool) {
	switch path {
	case "/scep":
		return "", "/scep", true
	case "/scep/pkiclient.exe":
		return "", "/scep/pkiclient.exe", true
	}
	if !strings.HasPrefix(path, "/scep/") {
		return "", "", false
	}
	rest := strings.TrimPrefix(path, "/scep/")
	if rest == "" {
		return "", "", false
	}
	if strings.HasSuffix(rest, "/pkiclient.exe") {
		pathID := strings.TrimSuffix(rest, "/pkiclient.exe")
		if pathID == "" || strings.Contains(pathID, "/") {
			return "", "", false
		}
		return pathID, "/scep/pkiclient.exe", true
	}
	if strings.Contains(rest, "/") {
		return "", "", false
	}
	return rest, "/scep", true
}

func validPathID(pathID string) bool {
	if pathID == "" {
		return true
	}
	if pathID[0] == '-' || pathID[len(pathID)-1] == '-' {
		return false
	}
	for _, r := range pathID {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return false
		}
	}
	return true
}

func errorsForPath(pathID, msg string) error {
	if pathID == "" {
		return fmt.Errorf("scep: root profile route: %s", msg)
	}
	return fmt.Errorf("scep: profile route %q: %s", pathID, msg)
}
