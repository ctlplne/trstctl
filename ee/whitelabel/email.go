package whitelabel

import (
	"bytes"
	"fmt"
	"html/template"

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
		LogoDataURI: template.URL(brand.LogoDataURI),
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
