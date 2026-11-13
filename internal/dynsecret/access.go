// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/cloudhttp"
)

// Access is what a lease's login can reach, read from the target system
// itself (G2): the resource, the login the lease holds there, and the grants
// or policies the target reports for that login. Nothing in it is secret.
type Access struct {
	TargetKind string   `json:"target_kind"`
	TargetRef  string   `json:"target_ref"`
	Login      string   `json:"login"`
	Grants     []string `json:"grants"`
	// Truncated counts the grants past MaxAccessGrants that are not listed.
	Truncated int `json:"truncated,omitempty"`
}

// MaxAccessGrants bounds what one lease records.
const MaxAccessGrants = 200

// Access target kinds.
const (
	AccessTargetPostgresDatabase = "postgresql_database"
	AccessTargetAWSIAMRole       = "aws_iam_role"
)

// Why a lease's access is unknown. A resolver returns one of these (wrapped);
// the reason recorded is the closed-set code AccessReason gives, never the
// target's own error text, which may echo a credential.
var (
	ErrAccessUnsupported  = errors.New("dynsecret: this provider cannot report what a lease reaches")
	ErrAccessUnreachable  = errors.New("dynsecret: the target could not be reached")
	ErrAccessLoginMissing = errors.New("dynsecret: the lease's login no longer exists on the target")
	ErrAccessDenied       = errors.New("dynsecret: the provider's credentials may not read the login's grants")
	ErrAccessUnreadable   = errors.New("dynsecret: the target's answer could not be read")
)

// AccessReason is the closed-set reason recorded for a lease whose access could
// not be read.
func AccessReason(err error) string {
	switch {
	case errors.Is(err, ErrAccessUnsupported):
		return "unsupported"
	case errors.Is(err, ErrAccessUnreachable):
		return "target_unreachable"
	case errors.Is(err, ErrAccessLoginMissing):
		return "login_missing"
	case errors.Is(err, ErrAccessDenied):
		return "access_denied"
	case errors.Is(err, ErrAccessUnreadable):
		return "unreadable_response"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return "error"
	}
}

// AccessResolver reads a lease's access from its target. It is read-only: it
// never changes a grant. When the target cannot be read it returns what it
// knows of the target with the error, and the caller records the grants as
// unknown — never as none.
type AccessResolver interface {
	ResolveAccess(ctx context.Context, backendRef string) (Access, error)
}

// ResolveAccess implements AccessResolver for a backend that can.
func (p *BackendProvider) ResolveAccess(ctx context.Context, backendRef string) (Access, error) {
	resolver, ok := p.backend.(AccessResolver)
	if !ok {
		return Access{}, ErrAccessUnsupported
	}
	return resolver.ResolveAccess(ctx, backendRef)
}

func boundGrants(access Access, grants []string) Access {
	sort.Strings(grants)
	if len(grants) > MaxAccessGrants {
		access.Truncated = len(grants) - MaxAccessGrants
		grants = grants[:MaxAccessGrants]
	}
	access.Grants = grants
	return access
}

// ResolveAccess reads the login role's privileges as PostgreSQL reports them:
// CONNECT on the provider's database, USAGE on schemas, table privileges and
// role memberships in the database the admin connection opens.
func (b *PostgresBackend) ResolveAccess(ctx context.Context, backendRef string) (Access, error) {
	access := Access{TargetKind: AccessTargetPostgresDatabase, TargetRef: postgresTargetRef(b.dsn.Bytes(), b.database), Login: strings.TrimSpace(backendRef)}
	if access.Login == "" {
		return access, fmt.Errorf("%w: the lease names no login role", ErrAccessLoginMissing)
	}
	conn, err := connectPostgresAdmin(ctx, b.dsn.Bytes())
	if err != nil {
		return access, ErrAccessUnreachable
	}
	defer func() { _ = conn.Close(ctx) }()
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, access.Login).Scan(&exists); err != nil {
		return access, postgresAccessError(err)
	}
	if !exists {
		return access, ErrAccessLoginMissing
	}
	rows, err := conn.Query(ctx, `
		SELECT 'CONNECT on database ' || quote_ident($2::text)
		 WHERE has_database_privilege($1, $2::text, 'CONNECT')
		UNION ALL
		SELECT 'USAGE on schema ' || quote_ident(n.nspname) FROM pg_namespace n
		 WHERE has_schema_privilege($1, n.oid, 'USAGE') AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'
		UNION ALL
		SELECT privilege_type || ' on ' || quote_ident(table_schema) || '.' || quote_ident(table_name)
		  FROM information_schema.table_privileges WHERE grantee = $1
		UNION ALL
		SELECT 'member of role ' || quote_ident(r.rolname) FROM pg_auth_members m
		  JOIN pg_roles r ON r.oid = m.roleid JOIN pg_roles u ON u.oid = m.member WHERE u.rolname = $1`,
		access.Login, b.database)
	if err != nil {
		return access, postgresAccessError(err)
	}
	defer rows.Close()
	var grants []string
	for rows.Next() {
		var grant string
		if err := rows.Scan(&grant); err != nil {
			return access, postgresAccessError(err)
		}
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		return access, postgresAccessError(err)
	}
	return boundGrants(access, grants), nil
}

func postgresAccessError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "42501" {
		return ErrAccessDenied
	}
	if pgconn.SafeToRetry(err) || errors.Is(err, context.DeadlineExceeded) {
		return ErrAccessUnreachable
	}
	return ErrAccessUnreadable
}

// postgresTargetRef names the database a backend reaches without credentials:
// postgresql://host[:port]/database from a URI DSN, or from host= and port= in
// a keyword DSN.
func postgresTargetRef(dsn []byte, database string) string {
	host := ""
	if _, _, authorityEnd, hostStart, ok := splitURIAuthority(dsn); ok && hostStart <= authorityEnd {
		host = string(dsn[hostStart:authorityEnd])
	} else {
		var port string
		for _, field := range bytes.Fields(dsn) {
			key, value, found := bytes.Cut(field, []byte("="))
			if !found {
				continue
			}
			switch string(bytes.ToLower(key)) {
			case "host":
				host = string(bytes.Trim(value, `'"`))
			case "port":
				port = string(bytes.Trim(value, `'"`))
			}
		}
		if host != "" && port != "" {
			host += ":" + port
		}
	}
	if host == "" {
		host = "localhost"
	}
	return "postgresql://" + host + "/" + database
}

// ResolveAccess reads the role an STS lease assumed, the managed and inline
// policies IAM lists for it and, statement by statement, what each allows or
// denies (G2-L1). The provider's credentials need iam:ListAttachedRolePolicies
// and iam:ListRolePolicies on the role, without which the grants are recorded
// as unknown, and iam:GetPolicy, iam:GetPolicyVersion and iam:GetRolePolicy to
// read the statements, without which each policy says its statements are
// unreadable.
func (b *AWSSTSBackend) ResolveAccess(ctx context.Context, backendRef string) (Access, error) {
	var ref awsSTSRef
	if err := json.Unmarshal([]byte(backendRef), &ref); err != nil || ref.RoleARN == "" {
		return Access{TargetKind: AccessTargetAWSIAMRole}, fmt.Errorf("%w: the lease names no role", ErrAccessLoginMissing)
	}
	access := Access{TargetKind: AccessTargetAWSIAMRole, TargetRef: ref.RoleARN, Login: ref.AssumedRoleID}
	if access.Login == "" {
		access.Login = ref.SessionName
	}
	roleName, ok := awsRoleNameFromARN(ref.RoleARN)
	if !ok {
		return access, fmt.Errorf("%w: %q is not an IAM role ARN", ErrAccessUnreadable, ref.RoleARN)
	}
	if b.iam == nil {
		return access, ErrAccessUnsupported
	}
	var grants []string
	var policies []awsPolicyRef
	for marker, pages := "", 0; pages < 20; pages++ {
		params := map[string]string{"Action": "ListAttachedRolePolicies", "Version": "2010-05-08", "RoleName": roleName, "MaxItems": "100"}
		if marker != "" {
			params["Marker"] = marker
		}
		raw, err := b.iam.call(ctx, params)
		if err != nil {
			return access, awsAccessError(err)
		}
		var page struct {
			Result struct {
				Policies []struct {
					Name string `xml:"PolicyName"`
					ARN  string `xml:"PolicyArn"`
				} `xml:"AttachedPolicies>member"`
				IsTruncated bool   `xml:"IsTruncated"`
				Marker      string `xml:"Marker"`
			} `xml:"ListAttachedRolePoliciesResult"`
		}
		if err := xml.Unmarshal(raw, &page); err != nil {
			return access, ErrAccessUnreadable
		}
		for _, p := range page.Result.Policies {
			grants = append(grants, "managed policy "+p.Name+" ("+p.ARN+")")
			policies = append(policies, awsPolicyRef{label: "managed policy " + p.Name, arn: p.ARN})
		}
		if !page.Result.IsTruncated || page.Result.Marker == "" {
			break
		}
		marker = page.Result.Marker
	}
	for marker, pages := "", 0; pages < 20; pages++ {
		params := map[string]string{"Action": "ListRolePolicies", "Version": "2010-05-08", "RoleName": roleName, "MaxItems": "100"}
		if marker != "" {
			params["Marker"] = marker
		}
		raw, err := b.iam.call(ctx, params)
		if err != nil {
			return access, awsAccessError(err)
		}
		var page struct {
			Result struct {
				Names       []string `xml:"PolicyNames>member"`
				IsTruncated bool     `xml:"IsTruncated"`
				Marker      string   `xml:"Marker"`
			} `xml:"ListRolePoliciesResult"`
		}
		if err := xml.Unmarshal(raw, &page); err != nil {
			return access, ErrAccessUnreadable
		}
		for _, name := range page.Result.Names {
			grants = append(grants, "inline policy "+name)
			policies = append(policies, awsPolicyRef{label: "inline policy " + name, name: name})
		}
		if !page.Result.IsTruncated || page.Result.Marker == "" {
			break
		}
		marker = page.Result.Marker
	}
	statements, err := b.readPolicyStatements(ctx, roleName, policies)
	if err != nil {
		return access, err
	}
	return boundGrants(access, append(grants, statements...)), nil
}

func awsAccessError(err error) error {
	var status *cloudhttp.StatusError
	switch {
	case errors.Is(err, errAWSIAMMissing):
		return ErrAccessLoginMissing
	case errors.As(err, &status) && (status.StatusCode == 401 || status.StatusCode == 403):
		return ErrAccessDenied
	case errors.As(err, &status) && status.StatusCode < 500:
		return ErrAccessUnreadable
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	default:
		return ErrAccessUnreachable
	}
}

// awsRoleNameFromARN returns the role name — the last path segment — of an IAM
// role ARN (arn:aws:iam::123456789012:role/path/name).
func awsRoleNameFromARN(arn string) (string, bool) {
	_, resource, ok := strings.Cut(arn, ":role/")
	if !ok || !strings.HasPrefix(arn, "arn:") {
		return "", false
	}
	name := resource[strings.LastIndex(resource, "/")+1:]
	return name, name != ""
}

// AWSIAMEndpointFor is where an STS provider reads role policies: the
// configured endpoint, else the global IAM endpoint of the region's partition.
// IAM requests are signed for the partition's home region either way.
func AWSIAMEndpointFor(region, configured string) (endpoint, signingRegion string) {
	switch {
	case strings.HasPrefix(region, "us-gov-"):
		endpoint, signingRegion = "https://iam.us-gov.amazonaws.com", "us-gov-west-1"
	case strings.HasPrefix(region, "cn-"):
		endpoint, signingRegion = "https://iam.cn-north-1.amazonaws.com.cn", "cn-north-1"
	default:
		endpoint, signingRegion = "https://iam.amazonaws.com", "us-east-1"
	}
	if configured = strings.TrimSpace(configured); configured != "" {
		endpoint = configured
	}
	return endpoint, signingRegion
}

// AccessGrantsSummary is a stable one-line rendering of the grants, for graph
// attributes.
func AccessGrantsSummary(a Access) string {
	out := strings.Join(a.Grants, "; ")
	if a.Truncated > 0 {
		out += "; and " + strconv.Itoa(a.Truncated) + " more"
	}
	return out
}
