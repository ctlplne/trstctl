// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"testing"
	"time"

	"trstctl.com/trstctl/internal/dynsecret"
)

func TestAWSSTSLeaseReadbackExposesNativeExpiryWithoutCredential(t *testing.T) {
	expiration := time.Date(2026, 10, 3, 15, 0, 0, 0, time.UTC)
	lease := dynsecret.Lease{
		ID: "sts-lease", Provider: "qa-aws-sts", Role: "reader",
		BackendRef: `{"role_arn":"arn:aws:iam::123456789012:role/trstctl-reader","session_name":"trstctl-reader-lease","assumed_role_id":"AROAREADER:trstctl-reader-lease","access_key_id":"ASIAEXAMPLE123456","expiration":"2026-10-03T15:00:00Z"}`,
	}
	readback := toDynamicLeaseResponse(lease, nil)
	if readback.NativeExpiresAt == nil || !readback.NativeExpiresAt.Equal(expiration) || len(readback.Credential) != 0 {
		t.Fatalf("AWS STS metadata omitted native expiry or replayed credential: %+v", readback)
	}
	lease.BackendRef = `{"username":"postgres-user"}`
	if readback := toDynamicLeaseResponse(lease, nil); readback.NativeExpiresAt != nil {
		t.Fatalf("non-STS provider reference received AWS expiry: %+v", readback)
	}
}
