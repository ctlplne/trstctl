// Package branding is the core white-label resolver seam.
//
// The built-in brand is served unless a Provider-tier implementation installs a
// source at the edition attach seam.
package branding

import (
	"context"
	"strings"
	"sync"
)

type Brand struct {
	ProductName    string            `json:"product_name"`
	LogoDataURI    string            `json:"logo_data_uri,omitempty"`
	LoginMessage   string            `json:"login_message,omitempty"`
	TokenOverrides map[string]string `json:"token_overrides,omitempty"`
	EmailFromName  string            `json:"email_from_name,omitempty"`
	EmailFooter    string            `json:"email_footer,omitempty"`
}

func Default() Brand {
	return Brand{ProductName: "trstctl"}
}

type Source interface {
	Resolve(ctx context.Context, host, tenantID string) Brand
	TenantForHost(ctx context.Context, host string) string
}

type defaultSource struct{}

func (defaultSource) Resolve(context.Context, string, string) Brand { return Default() }
func (defaultSource) TenantForHost(context.Context, string) string  { return "" }

var (
	mu  sync.RWMutex
	src Source = defaultSource{}
)

func SetSource(s Source) {
	mu.Lock()
	defer mu.Unlock()
	if s == nil {
		src = defaultSource{}
		return
	}
	src = s
}

func Resolve(ctx context.Context, host, tenantID string) Brand {
	mu.RLock()
	s := src
	mu.RUnlock()
	return s.Resolve(ctx, NormalizeHost(host), tenantID)
}

func TenantForHost(ctx context.Context, host string) string {
	mu.RLock()
	s := src
	mu.RUnlock()
	return s.TenantForHost(ctx, NormalizeHost(host))
}

func NormalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndexByte(host, ':'); i > 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	return strings.TrimSuffix(host, ".")
}
