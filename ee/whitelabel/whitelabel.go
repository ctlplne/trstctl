// Package whitelabel implements Provider-tier per-tenant branding.
package whitelabel

import (
	"context"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/branding"
)

type Record struct {
	TenantID       string            `json:"tenant_id,omitempty"`
	ProductName    string            `json:"product_name,omitempty"`
	LogoDataURI    string            `json:"logo_data_uri,omitempty"`
	LoginMessage   string            `json:"login_message,omitempty"`
	TokenOverrides map[string]string `json:"token_overrides,omitempty"`
	EmailFromName  string            `json:"email_from_name,omitempty"`
	EmailFooter    string            `json:"email_footer,omitempty"`
	CustomDomain   string            `json:"custom_domain,omitempty"`
	UpdatedBy      string            `json:"updated_by,omitempty"`
}

type Store interface {
	TenantBrand(context.Context, string) (*Record, error)
	TenantByDomain(context.Context, string) (*Record, error)
	ProviderBrand(context.Context) (*Record, error)
	SetTenantBrand(context.Context, Record) error
	SetProviderBrand(context.Context, Record) error
}

type Resolver struct {
	store Store
	ttl   time.Duration
	now   func() time.Time

	mu    sync.Mutex
	cache map[string]cachedRecord
}

type cachedRecord struct {
	record  *Record
	fetched time.Time
}

func NewResolver(store Store, ttl time.Duration) *Resolver {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &Resolver{store: store, ttl: ttl, now: time.Now, cache: map[string]cachedRecord{}}
}

func (r *Resolver) Invalidate() {
	r.mu.Lock()
	r.cache = map[string]cachedRecord{}
	r.mu.Unlock()
}

func (r *Resolver) Resolve(ctx context.Context, host, tenantID string) branding.Brand {
	if r == nil || r.store == nil {
		return branding.Default()
	}
	host = branding.NormalizeHost(host)
	var tenant *Record
	switch {
	case tenantID != "":
		tenant = r.lookup(ctx, "t:"+tenantID, func(context.Context) (*Record, error) {
			return r.store.TenantBrand(ctx, tenantID)
		})
	case host != "":
		tenant = r.lookup(ctx, "h:"+host, func(context.Context) (*Record, error) {
			return r.store.TenantByDomain(ctx, host)
		})
	}
	master := r.lookup(ctx, "master", func(context.Context) (*Record, error) {
		return r.store.ProviderBrand(ctx)
	})
	return merge(tenant, master)
}

func (r *Resolver) TenantForHost(ctx context.Context, host string) string {
	if r == nil || r.store == nil {
		return ""
	}
	host = branding.NormalizeHost(host)
	if host == "" {
		return ""
	}
	record := r.lookup(ctx, "h:"+host, func(context.Context) (*Record, error) {
		return r.store.TenantByDomain(ctx, host)
	})
	if record == nil {
		return ""
	}
	return record.TenantID
}

func (r *Resolver) lookup(ctx context.Context, key string, fetch func(context.Context) (*Record, error)) *Record {
	r.mu.Lock()
	if cached, ok := r.cache[key]; ok && r.now().Sub(cached.fetched) < r.ttl {
		r.mu.Unlock()
		return cloneRecord(cached.record)
	}
	r.mu.Unlock()
	record, err := fetch(ctx)
	if err != nil {
		return nil
	}
	r.mu.Lock()
	r.cache[key] = cachedRecord{record: cloneRecord(record), fetched: r.now()}
	r.mu.Unlock()
	return cloneRecord(record)
}

func merge(tenant, master *Record) branding.Brand {
	out := branding.Default()
	apply := func(record *Record) {
		if record == nil {
			return
		}
		if record.ProductName != "" {
			out.ProductName = record.ProductName
		}
		if record.LogoDataURI != "" {
			out.LogoDataURI = record.LogoDataURI
		}
		if record.LoginMessage != "" {
			out.LoginMessage = record.LoginMessage
		}
		if record.EmailFromName != "" {
			out.EmailFromName = record.EmailFromName
		}
		if record.EmailFooter != "" {
			out.EmailFooter = record.EmailFooter
		}
		for k, v := range record.TokenOverrides {
			if out.TokenOverrides == nil {
				out.TokenOverrides = map[string]string{}
			}
			out.TokenOverrides[k] = v
		}
	}
	apply(master)
	apply(tenant)
	return out
}

func cloneRecord(in *Record) *Record {
	if in == nil {
		return nil
	}
	cp := *in
	if in.TokenOverrides != nil {
		cp.TokenOverrides = map[string]string{}
		for k, v := range in.TokenOverrides {
			cp.TokenOverrides[k] = v
		}
	}
	return &cp
}
