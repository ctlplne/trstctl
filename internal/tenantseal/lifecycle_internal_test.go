// SPDX-License-Identifier: MPL-2.0

package tenantseal

import (
	"testing"

	"trstctl.com/trstctl/internal/store"
)

func TestTenantKeyDomainCanQueueSealOnlyFromTenantOnlyCryptoPosture(t *testing.T) {
	operationID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	base := store.TenantKeyDomain{
		TenantID:   "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		DomainID:   "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		Generation: 1, ProtectionMode: store.TenantKeyProtectionTenantDomain,
		State:       store.TenantKeyDomainStatePartial,
		WrapperKind: WrapperKindLocalFile, WrapperID: "operator-wrapper",
		WrappedDomainKEK: []byte("opaque wrapped domain key"),
		OperationID:      &operationID, OperationKind: store.TenantKeyOperationMigrate,
		OperationStatus:   store.TenantKeyOperationCompleted,
		ProgressCompleted: 10, ProgressTotal: 10,
		LegacyHistoryExposure: store.TenantKeyLegacyExternalArchivesPossible,
	}
	if !tenantKeyDomainCanQueueSeal(base.TenantID, base) {
		t.Fatal("completed tenant-only migration could not queue seal")
	}

	failedMigration := base
	failedMigration.OperationStatus = store.TenantKeyOperationFailed
	failedMigration.ProgressCompleted = 5
	if tenantKeyDomainCanQueueSeal(base.TenantID, failedMigration) {
		t.Fatal("failed dual-domain migration could queue seal and lose legacy reads")
	}

	failedSeal := base
	failedSeal.OperationKind = store.TenantKeyOperationSeal
	failedSeal.OperationStatus = store.TenantKeyOperationFailed
	failedSeal.Retryable = true
	if !tenantKeyDomainCanQueueSeal(base.TenantID, failedSeal) {
		t.Fatal("failed seal with tenant-only crypto could not be retried")
	}
}
