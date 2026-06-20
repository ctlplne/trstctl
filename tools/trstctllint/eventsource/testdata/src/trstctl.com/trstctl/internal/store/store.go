// Package store is a stand-in for the real read-model repository, so the
// analyzer can resolve a *store.Store receiver by its true import path.
package store

// Store is the read-model repository. Mutators write the relational read model;
// readers do not.
type Store struct{}

func (s *Store) CreateOwner(name string) (string, error)   { return "", nil }
func (s *Store) UpdateOwner(id, name string) error         { return nil }
func (s *Store) DeleteOwner(id string) error               { return nil }
func (s *Store) UpsertCertificate(fp string) error         { return nil }
func (s *Store) SetIdentityStatus(id, status string) error { return nil }
func (s *Store) RecordIssuedCert(tenantID, caID, serial string) error {
	return nil
}
func (s *Store) RevokeIssuedCert(tenantID, caID, serial string, reasonCode int) error {
	return nil
}
func (s *Store) InsertCRL(tenantID, caID string, number int64) error {
	return nil
}

// Reads — these must remain callable from a mutation handler.
func (s *Store) GetOwner(id string) (string, error) { return "", nil }
func (s *Store) ListOwners() ([]string, error)      { return nil, nil }
