// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/crypto/dbdsn"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

const PAMDatabaseGatewayStartSchemaVersion = 3

// PAMDatabaseGatewayBinding carries only public, validated route and trust.
type PAMDatabaseGatewayBinding struct {
	Route      dbdsn.GatewayRoute `json:"route"`
	CAPEM      string             `json:"ca_pem,omitempty"`
	ServerName string             `json:"server_name,omitempty"`
	Record     bool               `json:"record,omitempty"`
}

type PAMDatabaseGatewayStarted struct {
	PAMSessionStarted
	DatabaseGateway PAMDatabaseGatewayBinding `json:"database_gateway"`
	RequestDigest   string                    `json:"database_gateway_request_digest"`
	GatewayAddress  string                    `json:"database_gateway_address"`
}

func (p PAMDatabaseGatewayStarted) Intent() accessgateway.SessionIntent {
	db := p.DatabaseGateway
	return accessgateway.SessionIntent{SessionID: p.ID, TargetType: p.TargetType, TargetID: p.TargetID,
		ExpiresAt: p.ExpiresAt, TicketDigest: p.GatewayTicketDigest, RequiredAgentID: p.GatewayAgentID,
		CredentialRef: accessgateway.CredentialRef(p.ID), CommandPolicy: p.CommandPolicy,
		Record: db.Record, DatabaseRoute: &db.Route, DatabaseCAPEM: db.CAPEM, DatabaseServerName: db.ServerName}
}

func (p *Projector) applyPAMDatabaseGatewayStarted(ctx context.Context, tx pgx.Tx,
	session store.PAMSession, started PAMDatabaseGatewayStarted) error {
	host, port, addressErr := net.SplitHostPort(started.GatewayAddress)
	_, addressCheckErr := dbdsn.TCPAddress(host, port)
	digest, digestErr := hex.DecodeString(started.RequestDigest)
	if started.Delivery != "gateway" || dbdsn.GatewayDriver(started.TargetType) == "" || started.Status != "active" ||
		started.BackendRef == "" || started.SSHKeyID != "" || started.SSHPrincipal != "" || started.SSHSerial != 0 ||
		started.WebSignIn != nil || started.AccountRotationProvider != "" || addressErr != nil || addressCheckErr != nil ||
		digestErr != nil || len(digest) != 32 {
		return errors.New("projections: database gateway start requires a bound database session")
	}
	intent := started.Intent()
	if err := accessgateway.ValidateSessionIntent(intent); err != nil {
		return err
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	return p.store.ApplyPAMDatabaseGatewayStartedTx(ctx, tx, session, accessgateway.KindForIntent(intent),
		accessgateway.JobKey(session.ID), mtls.AgentRoleGateway, payload)
}

func pamDatabaseGatewayPrivacy(base events.PrivacyEventPolicy) events.PrivacyEventPolicy {
	base = pamCommandSessionPrivacy(base)
	const opaque = events.PrivacyFieldOpaqueExact
	base.Rules = append(base.Rules,
		privacyRule("/database_gateway_request_digest", opaque),
		privacyRule("/database_gateway_address", opaque),
		privacyRule("/database_gateway/route/revision", opaque),
		privacyRule("/database_gateway/route/provider_id", opaque),
		privacyRule("/database_gateway/route/hosts/*", opaque),
		privacyRule("/database_gateway/route/database", opaque),
		privacyRule("/database_gateway/route/tls", opaque),
		privacyRule("/database_gateway/route/source", opaque),
		privacyRule("/database_gateway/route/private_cidrs/*", opaque),
		privacyRule("/database_gateway/ca_pem", opaque),
		privacyRule("/database_gateway/server_name", opaque),
		privacyRule("/database_gateway/record", opaque))
	return base
}
