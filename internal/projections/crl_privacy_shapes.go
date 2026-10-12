// SPDX-License-Identifier: BUSL-1.1

package projections

import "time"

type privacyLegacyCRLPublishedV1 struct {
	CAID    string `json:"ca_id"`
	Number  int64  `json:"crl_number"`
	Revoked int    `json:"revoked"`
}

type privacyLegacyCRLPublishedV2 struct {
	CAID         string    `json:"ca_id"`
	Number       int64     `json:"crl_number"`
	DER          []byte    `json:"crl_der"`
	ThisUpdate   time.Time `json:"this_update"`
	NextUpdate   time.Time `json:"next_update"`
	RevokedCount int       `json:"revoked_count,omitempty"`
}
