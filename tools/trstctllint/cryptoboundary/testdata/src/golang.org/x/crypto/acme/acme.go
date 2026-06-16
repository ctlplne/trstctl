// Package acme is a stub of golang.org/x/crypto/acme for the cryptoboundary
// fixtures: the analyzer matches on import path (syntactically), so this only
// needs to exist so the fixture imports resolve.
package acme

// Client is a stand-in for the real acme.Client.
type Client struct{}
