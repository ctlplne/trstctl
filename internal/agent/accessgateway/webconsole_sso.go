// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// A273-O1: a console that signs its users in only through an identity
// provider (an OpenID Connect or SAML front door). The gateway starts the
// console's sign-in at its page and follows it to the provider named on the
// console's reviewed route — that origin and no other — fills the provider's
// sign-in form itself and follows the answer back to the console, which
// finishes the sign-in with the provider directly and sets its own session
// cookie. The browser never reaches the provider; the provider's cookies are
// the gateway's own and reach neither the console nor the browser.

// webSSOHops bounds the redirects one sign-in request follows across the
// console and its provider.
const webSSOHops = 8

// ssoSignInLocked runs the single sign-on. While the provider still holds the
// gateway's session with it, the console's sign-in completes without a
// password; otherwise the provider's form is filled once.
func (s *webConsoleState) ssoSignInLocked(ctx context.Context, c *webConsoleClient) error {
	if c.idp == nil || c.idpTransport == nil {
		return refusedSignIn("the console's route names no identity provider")
	}
	start := c.target.ResolveReference(&url.URL{Path: c.in.LoginPath})
	page, pageURL, status, err := s.fetchAcrossLocked(ctx, c, http.MethodGet, start, nil, nil)
	if err != nil {
		return err
	}
	if sameOrigin(pageURL, c.target) {
		if status < 400 && !hasSignInForm(page, c.in.PasswordField) {
			c.event("web", "sign-in", "sso "+webOrigin(c.idp)+": signed in with the provider's session")
			return nil
		}
		return refusedSignIn("the console's sign-in did not reach its identity provider (HTTP %d)", status)
	}
	if status != http.StatusOK {
		return refusedSignIn("the identity provider's sign-in page answered %d", status)
	}
	form, ok := findSignInForm(page, c.in.PasswordField)
	if !ok {
		return refusedSignIn("the identity provider's sign-in page has no form with the %s field", c.in.PasswordField)
	}
	if strings.EqualFold(form.method, http.MethodGet) {
		return refusedSignIn("the identity provider's sign-in form would put the password in a URL")
	}
	action, err := pageURL.Parse(form.action)
	if err != nil || !sameOrigin(action, c.idp) {
		return refusedSignIn("the identity provider's sign-in form posts off its origin")
	}
	action.Fragment = ""
	body := form.encode(c.in.UsernameField, c.account.username, c.in.PasswordField, c.account.secret)
	defer secret.Wipe(body)
	final, finalURL, status, err := s.fetchAcrossLocked(ctx, c, http.MethodPost, action, body, pageURL)
	switch {
	case err != nil:
		err = refusedSignIn("the answer to the sign-in was lost: %v", err)
	case status >= 400:
		err = refusedSignIn("the sign-in was refused (HTTP %d)", status)
	case sameOrigin(finalURL, c.idp) && hasSignInForm(final, c.in.PasswordField):
		err = refusedSignIn("the identity provider refused the sign-in")
	case !sameOrigin(finalURL, c.target):
		err = refusedSignIn("the sign-in did not return to the console")
	}
	outcome := "signed in"
	if err != nil {
		outcome = "refused"
	}
	c.event("web", "sign-in", "sso POST "+webOrigin(c.idp)+action.Path+": "+outcome)
	return err
}

// fetchAcrossLocked makes one sign-in request and follows its redirects
// between the console and its identity provider, each reached on its own
// transport and holding its own cookies. A redirect to any other origin is
// refused. It returns the final page (bounded), its URL and its status.
func (s *webConsoleState) fetchAcrossLocked(ctx context.Context, c *webConsoleClient, method string, u *url.URL, body []byte, referer *url.URL) ([]byte, *url.URL, int, error) {
	for hop := 0; ; hop++ {
		toIdP := sameOrigin(u, c.idp)
		if !toIdP && !sameOrigin(u, c.target) {
			return nil, nil, 0, refusedSignIn("the sign-in redirects off the console and its identity provider")
		}
		var reader io.Reader = http.NoBody
		if body != nil {
			reader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
		if err != nil {
			return nil, nil, 0, err
		}
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		req.Header.Set("Accept-Encoding", "identity")
		if body != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", webOrigin(u))
		}
		if referer != nil {
			req.Header.Set("Referer", referer.String())
		}
		transport, cookie := c.transport, s.cookieHeaderLocked(nil)
		if toIdP {
			transport, cookie = c.idpTransport, s.idpCookieHeaderLocked()
		}
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		resp, err := transport.RoundTrip(req)
		if err != nil {
			return nil, nil, 0, errors.New("accessgateway: the console or its identity provider is unreachable")
		}
		for _, set := range resp.Cookies() {
			if toIdP {
				s.keepIdPLocked(set)
			} else {
				s.keepLocked(set)
			}
		}
		page, readErr := io.ReadAll(io.LimitReader(resp.Body, webPageBytes))
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, nil, 0, errors.New("accessgateway: the sign-in's answer was cut short")
		}
		location := resp.Header.Get("Location")
		if resp.StatusCode < 300 || resp.StatusCode > 399 || location == "" {
			return page, u, resp.StatusCode, nil
		}
		if hop >= webSSOHops {
			return nil, nil, 0, refusedSignIn("the sign-in redirects too often")
		}
		next, err := u.Parse(location)
		if err != nil {
			return nil, nil, 0, refusedSignIn("the sign-in redirects to an invalid address")
		}
		if resp.StatusCode != http.StatusTemporaryRedirect && resp.StatusCode != http.StatusPermanentRedirect {
			method, body = http.MethodGet, nil
		}
		referer, u = u, next
	}
}
