// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/protocols/acme"
)

// The ACME admin seams (A52). One mount binds one tenant, so a caller for a
// different tenant sees an unserved list, never another tenant's accounts.

func (s *Server) acmeAccounts(ctx context.Context, tenantID string) (api.ACMEAccountList, error) {
	out := api.ACMEAccountList{GeneratedAt: time.Now().UTC(), Items: []api.ACMEAccount{}}
	sp := s.protocols
	if sp == nil || sp.acme == nil || sp.acmeTenant == "" || sp.acmeTenant != tenantID {
		return out, nil
	}
	out.Served = true
	accounts, err := sp.acme.AccountsContext(ctx)
	if err != nil {
		return out, err
	}
	for _, acct := range accounts {
		out.Items = append(out.Items, toAPIACMEAccount(acct))
	}
	return out, nil
}

func toAPIACMEAccount(in acme.AccountSummary) api.ACMEAccount {
	return api.ACMEAccount{ID: in.ID, Status: in.Status, Contact: append([]string(nil), in.Contact...),
		EABKeyID: in.EABKeyID, Orders: in.Orders, Certificates: in.Certificates}
}

// acmeAccountOrders lists one account's orders and resolves each issued
// leaf to its inventory row, so the console can hand the exact certificate
// id to the governed revocation path.
func (s *Server) acmeAccountOrders(ctx context.Context, tenantID, accountID string) (api.ACMEOrderList, error) {
	out := api.ACMEOrderList{AccountID: accountID, GeneratedAt: time.Now().UTC(), Items: []api.ACMEOrder{}}
	sp := s.protocols
	if sp == nil || sp.acme == nil || sp.acmeTenant == "" || sp.acmeTenant != tenantID {
		return out, nil
	}
	out.Served = true
	orders, err := sp.acme.OrdersContext(ctx, accountID)
	if errors.Is(err, acme.ErrNoSuchAccount) {
		return out, api.ErrACMEAccountNotFound
	}
	if err != nil {
		return out, err
	}
	for _, o := range orders {
		row := api.ACMEOrder{
			ID: o.ID, AccountID: o.AccountID, Status: o.Status, Identifiers: append([]string(nil), o.Identifiers...),
			Profile: o.Profile, AuthMode: o.AuthMode, Replaces: o.Replaces,
			CertificateID: o.CertificateID, CertificateSerial: o.CertificateSerial, CertificateFingerprint: o.CertificateFingerprint,
			Revoked: o.Revoked, Authorizations: []api.ACMEAuthorization{}, CreatedAt: o.CreatedAt,
		}
		if o.CertificateFingerprint != "" && s.store != nil {
			cert, err := s.store.GetCertificateByFingerprint(ctx, tenantID, o.CertificateFingerprint)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return out, err
			}
			if err == nil {
				row.CertificateRecordID = cert.ID
				if cert.Status == "revoked" {
					row.Revoked = true
				}
			}
		}
		for _, az := range o.Authorizations {
			authz := api.ACMEAuthorization{ID: az.ID, Domain: az.Domain, Status: az.Status, Challenges: []api.ACMEChallenge{}, CreatedAt: az.CreatedAt}
			for _, ch := range az.Challenges {
				authz.Challenges = append(authz.Challenges, api.ACMEChallenge{ID: ch.ID, Type: ch.Type, Status: ch.Status})
			}
			row.Authorizations = append(row.Authorizations, authz)
		}
		out.Items = append(out.Items, row)
	}
	return out, nil
}

func (s *Server) deactivateACMEAccount(ctx context.Context, tenantID, accountID string) (api.ACMEAccount, error) {
	sp := s.protocols
	if sp == nil || sp.acme == nil || sp.acmeTenant == "" || sp.acmeTenant != tenantID {
		return api.ACMEAccount{}, api.ErrACMEAccountNotFound
	}
	acct, err := sp.acme.DeactivateAccountContext(ctx, accountID)
	if errors.Is(err, acme.ErrNoSuchAccount) {
		return api.ACMEAccount{}, api.ErrACMEAccountNotFound
	}
	if err != nil {
		return api.ACMEAccount{}, err
	}
	return toAPIACMEAccount(acct), nil
}
