// SPDX-License-Identifier: LicenseRef-trstctl-EE

package enterpriseauth

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode/utf16"

	ldap "github.com/go-ldap/ldap/v3"

	"trstctl.com/trstctl/internal/auth"
)

// LDAPVerifier authenticates a human user by LDAP simple bind, then normalizes
// the directory result into auth.Claims so the existing tenant mapper can bind
// directory groups to trstctl tenants and roles.
type LDAPVerifier struct {
	URL string

	UserDNTemplate   string
	BindDN           string
	BindPassword     []byte
	UserSearchBaseDN string
	UserFilter       string

	GroupSearchBaseDN  string
	GroupFilter        string
	GroupNameAttribute string
	EmailAttribute     string

	Timeout time.Duration
	// PasswordChangeMode selects how ChangePassword writes the new password
	// (A81): config.LDAPPasswordChangeExop or LDAPPasswordChangeActiveDirectory.
	PasswordChangeMode string
}

// LDAPPasswordRefusedError is a directory's refusal of a new password (its
// policy: history, length, complexity, minimum age); Reason is the
// directory's own wording, safe to show the user.
type LDAPPasswordRefusedError struct{ Reason string }

func (e *LDAPPasswordRefusedError) Error() string {
	return "auth: the directory refused the new password: " + e.Reason
}

// Verify binds the supplied username/password to LDAP, reads the user's email
// and groups, and returns auth.Claims. The password belongs to the caller; Verify
// never stores it and rejects empty passwords so an LDAP unauthenticated bind
// cannot become a login.
func (v LDAPVerifier) Verify(ctx context.Context, username string, password []byte) (auth.Claims, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return auth.Claims{}, errors.New("auth: LDAP username is required")
	}
	if len(password) == 0 {
		return auth.Claims{}, errors.New("auth: LDAP password is required")
	}
	timeout := v.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	conn, err := ldap.DialURL(v.URL, ldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
	if err != nil {
		return auth.Claims{}, fmt.Errorf("auth: LDAP dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	conn.SetTimeout(timeout)
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return auth.Claims{}, err
		}
	}

	userDN, email, err := v.resolveUser(conn, username)
	if err != nil {
		return auth.Claims{}, err
	}
	if err := bindUser(conn, userDN, password); err != nil {
		if errors.Is(err, auth.ErrPasswordChangeRequired) {
			return auth.Claims{}, err
		}
		return auth.Claims{}, fmt.Errorf("auth: LDAP bind failed")
	}
	if v.BindDN != "" {
		if err := bind(conn, v.BindDN, v.BindPassword); err != nil {
			return auth.Claims{}, fmt.Errorf("auth: LDAP service rebind for group lookup: %w", err)
		}
	}
	if email == "" {
		email = v.lookupUserEmail(conn, userDN)
	}
	groups, err := v.lookupGroups(conn, username, userDN)
	if err != nil {
		return auth.Claims{}, err
	}
	return auth.Claims{
		Subject: userDN,
		Email:   email,
		Issuer:  "ldap:" + v.URL,
		Groups:  groups,
	}, nil
}

func (v LDAPVerifier) resolveUser(conn *ldap.Conn, username string) (dn string, email string, err error) {
	if strings.TrimSpace(v.UserDNTemplate) != "" {
		return strings.ReplaceAll(v.UserDNTemplate, "{username}", ldap.EscapeDN(username)), "", nil
	}
	if v.BindDN != "" {
		if err := bind(conn, v.BindDN, v.BindPassword); err != nil {
			return "", "", fmt.Errorf("auth: LDAP service bind: %w", err)
		}
	}
	filter := ldapTemplate(v.UserFilter, username, "")
	attrs := uniqueNonEmpty("dn", v.EmailAttribute)
	req := ldap.NewSearchRequest(v.UserSearchBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 5, false, filter, attrs, nil)
	req.EnforceSizeLimit = true
	res, err := conn.Search(req)
	if err != nil {
		return "", "", fmt.Errorf("auth: LDAP user search: %w", err)
	}
	if len(res.Entries) != 1 {
		return "", "", fmt.Errorf("auth: LDAP user search returned %d entries", len(res.Entries))
	}
	entry := res.Entries[0]
	return entry.DN, entry.GetAttributeValue(v.EmailAttribute), nil
}

func (v LDAPVerifier) lookupUserEmail(conn *ldap.Conn, userDN string) string {
	if strings.TrimSpace(v.EmailAttribute) == "" {
		return ""
	}
	req := ldap.NewSearchRequest(userDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, "(objectClass=*)", []string{v.EmailAttribute}, nil)
	req.EnforceSizeLimit = true
	res, err := conn.Search(req)
	if err != nil || len(res.Entries) == 0 {
		return ""
	}
	return res.Entries[0].GetAttributeValue(v.EmailAttribute)
}

func (v LDAPVerifier) lookupGroups(conn *ldap.Conn, username, userDN string) ([]string, error) {
	if strings.TrimSpace(v.GroupSearchBaseDN) == "" || strings.TrimSpace(v.GroupFilter) == "" {
		return nil, nil
	}
	attr := v.GroupNameAttribute
	if strings.TrimSpace(attr) == "" {
		attr = "cn"
	}
	filter := ldapTemplate(v.GroupFilter, username, userDN)
	req := ldap.NewSearchRequest(v.GroupSearchBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 100, 5, false, filter, []string{attr}, nil)
	req.EnforceSizeLimit = true
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("auth: LDAP group search: %w", err)
	}
	seen := map[string]struct{}{}
	var groups []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		groups = append(groups, s)
	}
	for _, entry := range res.Entries {
		add(entry.DN)
		for _, value := range entry.GetAttributeValues(attr) {
			add(value)
		}
	}
	return groups, nil
}

func bind(conn *ldap.Conn, dn string, password []byte) error {
	if len(password) == 0 {
		return errors.New("empty LDAP bind password")
	}
	return conn.Bind(dn, string(password))
}

func ldapTemplate(tmpl, username, userDN string) string {
	out := strings.ReplaceAll(tmpl, "{username}", ldap.EscapeFilter(username))
	out = strings.ReplaceAll(out, "{user_dn}", ldap.EscapeFilter(userDN))
	return out
}

func uniqueNonEmpty(values ...string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || v == "dn" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// bindUser binds as the user with the password-policy control attached, so a
// correct but expired credential (OpenLDAP ppolicy: passwordExpired or
// changeAfterReset; Active Directory: "data 773" must-change or "data 532"
// expired in the diagnostic) surfaces as ErrPasswordChangeRequired rather than
// as a plain refusal (A81).
func bindUser(conn *ldap.Conn, dn string, password []byte) error {
	if len(password) == 0 {
		return errors.New("empty LDAP bind password")
	}
	result, err := conn.SimpleBind(&ldap.SimpleBindRequest{
		Username: dn, Password: string(password), Controls: []ldap.Control{ldap.NewControlBeheraPasswordPolicy()},
	})
	if err != nil {
		if ldapPasswordChangeRequired(err, nil) {
			return auth.ErrPasswordChangeRequired
		}
		return err
	}
	if result != nil && ldapPasswordChangeRequired(nil, result.Controls) {
		return auth.ErrPasswordChangeRequired
	}
	return nil
}

// ldapPasswordChangeRequired classifies a bind outcome.
func ldapPasswordChangeRequired(err error, controls []ldap.Control) bool {
	if err != nil {
		var ldapErr *ldap.Error
		if errors.As(err, &ldapErr) && ldapErr.ResultCode == ldap.LDAPResultInvalidCredentials {
			text := ldapErr.Err.Error()
			if strings.Contains(text, "data 773") || strings.Contains(text, "data 532") {
				return true
			}
		}
		return false
	}
	for _, control := range controls {
		if policy, ok := control.(*ldap.ControlBeheraPasswordPolicy); ok {
			// Behera error codes: 0 passwordExpired, 2 changeAfterReset.
			if policy.Error == 0 || policy.Error == 2 {
				return true
			}
		}
	}
	return false
}

// ChangePassword proves the current password by binding as the user, then
// changes it the way the directory expects (A81). A wrong current password is
// a plain bind failure; the directory's refusal of the new password comes
// back as LDAPPasswordRefusedError with its reason.
func (v LDAPVerifier) ChangePassword(ctx context.Context, username string, current, next []byte) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("auth: LDAP username is required")
	}
	if len(current) == 0 || len(next) == 0 {
		return errors.New("auth: current and new passwords are required")
	}
	if string(current) == string(next) {
		return &LDAPPasswordRefusedError{Reason: "the new password must differ from the current one"}
	}
	timeout := v.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	conn, err := ldap.DialURL(v.URL, ldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
	if err != nil {
		return fmt.Errorf("auth: LDAP dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	conn.SetTimeout(timeout)
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	userDN, _, err := v.resolveUser(conn, username)
	if err != nil {
		return err
	}
	if err := conn.Bind(userDN, string(current)); err != nil {
		var ldapErr *ldap.Error
		if errors.As(err, &ldapErr) && ldapErr.ResultCode == ldap.LDAPResultInvalidCredentials && !ldapPasswordChangeRequired(err, nil) {
			return errors.New("auth: LDAP bind failed")
		}
		if !ldapPasswordChangeRequired(err, nil) {
			return fmt.Errorf("auth: LDAP bind: %w", err)
		}
		// An expired credential still binds for the change on directories
		// that grant it; Active Directory does not, which is its policy.
	}
	switch strings.ToLower(strings.TrimSpace(v.PasswordChangeMode)) {
	case "", "exop":
		_, err = conn.PasswordModify(ldap.NewPasswordModifyRequest("", string(current), string(next)))
	case "active_directory":
		modify := ldap.NewModifyRequest(userDN, nil)
		modify.Delete("unicodePwd", []string{string(adPasswordValue(current))})
		modify.Add("unicodePwd", []string{string(adPasswordValue(next))})
		err = conn.Modify(modify)
	default:
		return fmt.Errorf("auth: unknown LDAP password change mode %q", v.PasswordChangeMode)
	}
	if err != nil {
		return classifyPasswordChangeError(err)
	}
	return nil
}

func classifyPasswordChangeError(err error) error {
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		switch ldapErr.ResultCode {
		case ldap.LDAPResultConstraintViolation, ldap.LDAPResultUnwillingToPerform, ldap.LDAPResultInsufficientAccessRights, ldap.LDAPResultInvalidCredentials:
			reason := strings.TrimSpace(ldapErr.Err.Error())
			if reason == "" {
				reason = ldap.LDAPResultCodeMap[ldapErr.ResultCode]
			}
			return &LDAPPasswordRefusedError{Reason: reason}
		}
	}
	return fmt.Errorf("auth: LDAP password change: %w", err)
}

// adPasswordValue encodes a password the way Active Directory's unicodePwd
// attribute expects: the password in double quotes, as UTF-16LE.
func adPasswordValue(password []byte) []byte {
	quoted := utf16.Encode([]rune(`"` + string(password) + `"`))
	out := make([]byte, 0, 2*len(quoted))
	for _, unit := range quoted {
		out = binary.LittleEndian.AppendUint16(out, unit)
	}
	return out
}
