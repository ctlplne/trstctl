// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

type gcpGatewayMaterial struct {
	key         *secret.Buffer
	id, subject string
}

func parseGCPGatewayMaterial(raw []byte, subject string) (*gcpGatewayMaterial, error) {
	var c struct {
		Type    string           `json:"type"`
		ID      string           `json:"private_key_id"`
		Subject string           `json:"client_email"`
		Key     secret.JSONBytes `json:"private_key"`
	}
	defer func() { secret.Wipe(c.Key) }()
	if len(raw) > 64<<10 || json.Unmarshal(raw, &c) != nil || c.Type != "service_account" || c.Subject != subject || c.ID == "" || len(c.ID) > 256 || len(c.Key) == 0 {
		return nil, errors.New("accessgateway: invalid Google Cloud credential binding")
	}
	der, err := crypto.PublicKeyDERFromPEMKey(c.Key)
	if err != nil {
		return nil, errors.New("accessgateway: invalid Google Cloud key")
	}
	pub, err := crypto.ParsePublicKeyPEM(crypto.MarshalPublicKeyPEM(der))
	if err != nil || (pub.Algorithm != crypto.RSA2048 && pub.Algorithm != crypto.RSA3072 && pub.Algorithm != crypto.RSA4096) {
		return nil, errors.New("accessgateway: Google Cloud requires an RSA key")
	}
	held, err := secret.NewFrom(c.Key)
	if err != nil {
		return nil, err
	}
	return &gcpGatewayMaterial{key: held, id: c.ID, subject: c.Subject}, nil
}

func gcpAssertion(material *gcpGatewayMaterial, intent SessionIntent, now time.Time) ([]byte, error) {
	expires := earliest(intent.ExpiresAt, now.Add(time.Hour))
	if expires.Unix() <= now.Unix() {
		return nil, errors.New("accessgateway: OAuth session expired")
	}
	var assertion []byte
	err := material.key.Use(func(key []byte) error {
		var err error
		assertion, err = crypto.SignJWTWithPEMKeyBytes(key, material.id, map[string]any{"iss": material.subject, "scope": strings.Join(intent.OAuthScopes, " "), "aud": intent.OAuthTokenEndpoint, "iat": now.Unix(), "exp": expires.Unix()})
		return err
	})
	return assertion, err
}

func gcpExchange(ctx context.Context, material *gcpGatewayMaterial, intent SessionIntent, dial func(context.Context, string, string) (net.Conn, error)) (*secret.Buffer, time.Time, error) {
	assertion, err := gcpAssertion(material, intent, time.Now())
	if err != nil {
		return nil, time.Time{}, err
	}
	form := append([]byte("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="), assertion...)
	secret.Wipe(assertion)
	held, err := secret.NewFrom(form)
	secret.Wipe(form)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer held.Destroy()
	return oauthExchange(ctx, held, intent, dial, time.Hour)
}

func recordGCP(rec *connRecorder, material *gcpGatewayMaterial, token *secret.Buffer, kind string, head []byte, size int) {
	if rec == nil {
		return
	}
	var masked []byte
	err := material.key.Use(func(key []byte) error {
		return token.Use(func(value []byte) error {
			masked = maskCredentialHead(head, size, key, value)
			return nil
		})
	})
	if err != nil {
		return
	}
	defer secret.Wipe(masked)
	rec.event("gcp", kind, "gcp: "+boundedHTTPText(masked, max(size, len(masked))), 0)
}

func serveGCP(ctx context.Context, client net.Conn, raw []byte, intent SessionIntent, dial func(context.Context, string, string) (net.Conn, error), rec *connRecorder) error {
	material, err := parseGCPGatewayMaterial(raw, intent.OAuthSubject)
	secret.Wipe(raw)
	if err != nil {
		return err
	}
	defer material.key.Destroy()
	return serveOAuthHTTP(ctx, client, intent, dial, rec, func(ctx context.Context) (*secret.Buffer, time.Time, error) {
		return gcpExchange(ctx, material, intent, dial)
	}, func(token *secret.Buffer, kind string, head []byte, size int) {
		recordGCP(rec, material, token, kind, head, size)
	})
}

// RFC 6750 b64token: header injection and arbitrary controls are refused before
// any bearer bytes are serialized. Padding is allowed only at the end.
func validOAuthBearer(raw []byte) bool {
	padding := false
	for _, b := range raw {
		if b == '=' {
			padding = true
			continue
		}
		allowed := b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '.' || b == '_' || b == '~' || b == '+' || b == '/'
		if padding || !allowed {
			return false
		}
	}
	return len(raw) > 0 && raw[0] != '='
}
