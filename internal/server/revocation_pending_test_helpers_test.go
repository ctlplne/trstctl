// SPDX-License-Identifier: BUSL-1.1

package server

import "context"

// The fixture stores have no command receiver; they model only projected
// issuer rows. Served integration tests use the real PostgreSQL receiver.
func (*fakeRevocationStore) PendingCertificateRevocationForSerial(context.Context, string, string, string) (bool, error) {
	return false, nil
}
func (*fakeRevocationStore) PendingCertificateRevocationForCA(context.Context, string, string) (bool, error) {
	return false, nil
}
func (*fakeRevocationStore) CountRevokedCerts(context.Context, string, string) (int64, error) {
	// This public-read fixture has no revoked issuer rows. Its list method
	// deliberately refuses generation work during a GET.
	return 0, nil
}
func (*freshCRLStore) PendingCertificateRevocationForSerial(context.Context, string, string, string) (bool, error) {
	return false, nil
}
func (*freshCRLStore) PendingCertificateRevocationForCA(context.Context, string, string) (bool, error) {
	return false, nil
}
func (f *freshCRLStore) CountRevokedCerts(ctx context.Context, tenantID, caID string) (int64, error) {
	rows, err := f.ListRevokedCerts(ctx, tenantID, caID)
	return int64(len(rows)), err
}
func (*multiCRLStore) PendingCertificateRevocationForSerial(context.Context, string, string, string) (bool, error) {
	return false, nil
}
func (*multiCRLStore) PendingCertificateRevocationForCA(context.Context, string, string) (bool, error) {
	return false, nil
}
func (f *multiCRLStore) CountRevokedCerts(ctx context.Context, tenantID, caID string) (int64, error) {
	rows, err := f.ListRevokedCerts(ctx, tenantID, caID)
	return int64(len(rows)), err
}
func (*opensslRevocationStore) PendingCertificateRevocationForSerial(context.Context, string, string, string) (bool, error) {
	return false, nil
}
func (*opensslRevocationStore) PendingCertificateRevocationForCA(context.Context, string, string) (bool, error) {
	return false, nil
}
func (f *opensslRevocationStore) CountRevokedCerts(ctx context.Context, tenantID, caID string) (int64, error) {
	rows, err := f.ListRevokedCerts(ctx, tenantID, caID)
	return int64(len(rows)), err
}
func (*ocspResponderRotationStore) PendingCertificateRevocationForSerial(context.Context, string, string, string) (bool, error) {
	return false, nil
}
func (*ocspResponderRotationStore) PendingCertificateRevocationForCA(context.Context, string, string) (bool, error) {
	return false, nil
}
func (f *ocspResponderRotationStore) CountRevokedCerts(ctx context.Context, tenantID, caID string) (int64, error) {
	rows, err := f.ListRevokedCerts(ctx, tenantID, caID)
	return int64(len(rows)), err
}
