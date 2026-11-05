// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/crypto/secret"
)

type azureGatewayMaterial struct {
	value          *secret.Buffer
	client, tenant string
}

func parseAzureGatewayMaterial(raw []byte, client, tenant string) (*azureGatewayMaterial, error) {
	var c struct {
		Client string           `json:"client_id"`
		Tenant string           `json:"tenant_id"`
		Value  secret.JSONBytes `json:"client_secret"`
	}
	defer func() { secret.Wipe(c.Value) }()
	if len(raw) > 64<<10 || json.Unmarshal(raw, &c) != nil || c.Client != client || c.Tenant != tenant || client == "" || tenant == "" || len(c.Value) == 0 || len(c.Value) > 32<<10 {
		return nil, errors.New("accessgateway: invalid Azure credential binding")
	}
	value, err := secret.NewFrom(c.Value)
	if err != nil {
		return nil, err
	}
	return &azureGatewayMaterial{value, client, tenant}, nil
}
func appendOAuthFormValue(dst, value []byte) []byte {
	const digits = "0123456789ABCDEF"
	for _, b := range value {
		switch {
		case b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.' || b == '~':
			dst = append(dst, b)
		case b == ' ':
			dst = append(dst, '+')
		default:
			dst = append(dst, '%', digits[b>>4], digits[b&15])
		}
	}
	return dst
}
func azureExchange(ctx context.Context, material *azureGatewayMaterial, intent SessionIntent, dial func(context.Context, string, string) (net.Conn, error)) (*secret.Buffer, time.Time, error) {
	if !time.Now().Before(intent.ExpiresAt) {
		return nil, time.Time{}, errors.New("accessgateway: Azure session expired")
	}
	form := []byte("grant_type=client_credentials&client_id=" + url.QueryEscape(material.client) + "&scope=" + url.QueryEscape(strings.Join(intent.OAuthScopes, " ")) + "&client_secret=")
	err := material.value.Use(func(value []byte) error { form = appendOAuthFormValue(form, value); return nil })
	if err != nil {
		secret.Wipe(form)
		return nil, time.Time{}, err
	}
	held, err := secret.NewFrom(form)
	secret.Wipe(form)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer held.Destroy()
	// Native Entra tokens may outlive the password/session. Honor expires_in as
	// metadata while the local session deadline always bounds gateway use.
	return oauthExchange(ctx, held, intent, dial, 28*time.Hour)
}
func serveAzure(ctx context.Context, client net.Conn, raw []byte, intent SessionIntent, dial func(context.Context, string, string) (net.Conn, error), rec *connRecorder) error {
	material, err := parseAzureGatewayMaterial(raw, intent.OAuthSubject, intent.OAuthTenant)
	secret.Wipe(raw)
	if err != nil {
		return err
	}
	defer material.value.Destroy()
	return serveOAuthHTTP(ctx, client, intent, dial, rec, func(ctx context.Context) (*secret.Buffer, time.Time, error) {
		return azureExchange(ctx, material, intent, dial)
	}, func(token *secret.Buffer, kind string, head []byte, size int) {
		if rec == nil {
			return
		}
		var masked []byte
		err := material.value.Use(func(value []byte) error {
			return token.Use(func(access []byte) error { masked = maskCredentialHead(head, size, value, access); return nil })
		})
		if err != nil {
			return
		}
		defer secret.Wipe(masked)
		rec.event("azure", kind, "azure: "+boundedHTTPText(masked, max(size, len(masked))), 0)
	})
}
