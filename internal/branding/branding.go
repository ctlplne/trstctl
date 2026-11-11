// SPDX-License-Identifier: BUSL-1.1

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

// PoweredBy is the attribution every surface that shows a white-label brand
// carries beside it (MSP-1): the console header and sign-in page, every email's
// header, the customer assurance report's cover and pages, and notifications.
// It is not a brand field, so no brand document can change or remove it.
const PoweredBy = "Powered by trstctl"

// PoweredByURL is where the attribution links.
const PoweredByURL = "https://trstctl.com"

// IsCustom reports whether b is a white-label brand: any field differs from the
// built-in brand. It is the one rule for when a surface shows PoweredBy, so a
// brand that changes only colors or only the email strings is still custom.
func IsCustom(b Brand) bool {
	name := strings.TrimSpace(b.ProductName)
	return (name != "" && name != Default().ProductName) || strings.TrimSpace(b.LogoDataURI) != "" ||
		strings.TrimSpace(b.LoginMessage) != "" || len(b.TokenOverrides) > 0 ||
		strings.TrimSpace(b.EmailFromName) != "" || strings.TrimSpace(b.EmailFooter) != ""
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

// PoweredByLine is PoweredBy when the tenant's resolved brand is a white-label
// brand and "" when it is the built-in brand. Notifications, tickets and posts
// sent for a tenant carry this line; it reads the brand, never a setting.
func PoweredByLine(ctx context.Context, tenantID string) string {
	if IsCustom(Resolve(ctx, "", tenantID)) {
		return PoweredBy
	}
	return ""
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
