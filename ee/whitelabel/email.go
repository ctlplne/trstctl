// SPDX-License-Identifier: LicenseRef-trstctl-EE

package whitelabel

import (
	"bytes"
	"fmt"
	"html/template"

	"encoding/base64"
	"net/url"
	"strings"
	"trstctl.com/trstctl/internal/branding"
)

type Email struct {
	Subject   string
	Preheader string
	BodyHTML  template.HTML
}

const emailTemplate = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>{{.Subject}}</title></head>
<body style="margin:0;padding:24px;background:#f6f7f9;font-family:Arial,Helvetica,sans-serif;color:#111827;">
<span style="display:none;max-height:0;overflow:hidden;">{{.Preheader}}</span>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0">
<tr><td align="center">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;padding:32px;">
<tr><td style="padding-bottom:16px;">
{{if .LogoDataURI}}<img src="{{.LogoDataURI}}" alt="{{.ProductName}}" height="32" style="display:block;">{{else}}<strong style="font-size:18px;">{{.ProductName}}</strong>{{end}}
</td></tr>
<tr><td style="font-size:16px;line-height:1.5;">{{.Body}}</td></tr>
<tr><td style="padding-top:24px;font-size:12px;color:#6b7280;">{{if .EmailFooter}}{{.EmailFooter}}{{else}}Sent by {{.ProductName}}.{{end}}</td></tr>
</table>
</td></tr>
</table>
</body>
</html>`

var emailTmpl = template.Must(template.New("email").Parse(emailTemplate))

func RenderEmail(brand branding.Brand, email Email) (html string, from string, err error) {
	if brand.ProductName == "" {
		brand = branding.Default()
	}
	var buf bytes.Buffer
	data := struct {
		Subject     string
		Preheader   string
		ProductName string
		LogoDataURI template.URL
		EmailFooter string
		Body        template.HTML
	}{
		Subject:     email.Subject,
		Preheader:   email.Preheader,
		ProductName: brand.ProductName,
		LogoDataURI: safeLogoURI(brand.LogoDataURI),
		EmailFooter: brand.EmailFooter,
		Body:        email.BodyHTML,
	}
	if err := emailTmpl.Execute(&buf, data); err != nil {
		return "", "", fmt.Errorf("whitelabel: render email: %w", err)
	}
	from = brand.EmailFromName
	if from == "" {
		from = brand.ProductName
	}
	return buf.String(), from, nil
}

// maxLogoURIBytes bounds an embedded logo. A data: URI is inlined into every
// outbound message, so an unbounded one is a cheap way to make the platform send
// megabytes per email on a tenant's behalf.
const maxLogoURIBytes = 256 * 1024

// safeLogoURI returns the branding logo source only when it is one this template
// can embed safely, and "" otherwise — in which case the template falls back to
// rendering the product name as text.
//
// brand.LogoDataURI is tenant-configurable and arrives as a plain string.
// Wrapping a tenant string in template.URL is an explicit instruction to
// html/template NOT to sanitise it (gosec G203), so without this check a tenant
// could set a javascript: or data:text/html payload and have it rendered into
// every outbound email sent under the platform's name.
func safeLogoURI(raw string) template.URL {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > maxLogoURIBytes {
		return ""
	}
	lower := strings.ToLower(s)
	switch {
	case strings.HasPrefix(lower, "https://"):
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return ""
		}
		return template.URL(s) // #nosec G203 -- scheme and host validated above; https only (CWE-79)
	case strings.HasPrefix(lower, "data:"):
		// Raster image data URIs only. SVG is excluded deliberately: it is an XML
		// document that can carry <script>, so "it is an image type" is not a
		// safety argument for it.
		for _, prefix := range []string{
			"data:image/png;base64,",
			"data:image/jpeg;base64,",
			"data:image/gif;base64,",
			"data:image/webp;base64,",
		} {
			if !strings.HasPrefix(lower, prefix) {
				continue
			}
			if _, err := base64.StdEncoding.DecodeString(s[len(prefix):]); err != nil {
				return ""
			}
			return template.URL(s) // #nosec G203 -- raster image data URI with a decodable base64 payload (CWE-79)
		}
	}
	return ""
}
