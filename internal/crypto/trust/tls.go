// SPDX-License-Identifier: BUSL-1.1

package trust

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
)

// The runtime list: the shipped list, plus whatever an operator adds in
// configuration. It is process-wide because outbound transports are built in
// many places that never see the configuration; SetOperator runs once at
// startup and transports built before or after it read the same list.
var (
	activeMu sync.RWMutex
	active   *List
)

// Active returns the list outbound TLS clients check: the shipped list merged
// with the operator's additions once SetOperator has run, the shipped list
// alone before that. The shipped entries can never be removed.
func Active() *List {
	activeMu.RLock()
	l := active
	activeMu.RUnlock()
	if l == nil {
		return Shipped()
	}
	return l
}

// SetOperator installs the operator's additions (a list in the shipped file's
// shape, from the trust.distrust_file configuration) on top of the shipped
// list. A nil extra resets to the shipped list.
func SetOperator(extra *List) error {
	merged, err := Shipped().Merge(extra)
	if err != nil {
		return err
	}
	activeMu.Lock()
	active = merged
	activeMu.Unlock()
	return nil
}

// DistrustError is the handshake failure a distrusted certificate causes. It
// names the entry so an operator reading a log knows which incident refused
// the connection and why.
type DistrustError struct {
	Entry   Entry
	Subject string
}

func (e *DistrustError) Error() string {
	return fmt.Sprintf("trust: refusing TLS connection: %s %q is distrusted as %q (%s)", e.Entry.Kind, e.Subject, e.Entry.Name, e.Entry.Reason)
}

// VerifyConnection returns the check installed as tls.Config.VerifyConnection
// on every outbound client. It runs after Go's own verification (which
// already drops chains through the eight eMudhra intermediates) and also on
// resumed sessions, which skip VerifyPeerCertificate. The connection is
// accepted if at least one verified chain contains no distrusted certificate
// by key or by certificate hash; a server that also presents an old
// cross-sign still connects through its clean chain, as Go's own distrust
// list treats it. When verification is off and VerifiedChains is empty (the
// loopback development client), the presented certificates are checked
// directly. A nil list means Active() at handshake time, so an operator
// addition applies to transports built before it was installed.
func VerifyConnection(list *List) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		l := list
		if l == nil {
			l = Active()
		}
		if len(cs.VerifiedChains) == 0 {
			if c, e, ok := l.MatchChain(cs.PeerCertificates); ok {
				return &DistrustError{Entry: e, Subject: c.Subject.String()}
			}
			return nil
		}
		var first *DistrustError
		for _, chain := range cs.VerifiedChains {
			c, e, ok := l.MatchChain(chain)
			if !ok {
				return nil
			}
			if first == nil {
				first = &DistrustError{Entry: e, Subject: c.Subject.String()}
			}
		}
		return first
	}
}

// HardenTLSConfig installs the distrust check on cfg, chaining after any check
// already there, and returns cfg (a new TLS 1.2+ config when cfg is nil).
func HardenTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	prev := cfg.VerifyConnection
	check := VerifyConnection(nil)
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if prev != nil {
			if err := prev(cs); err != nil {
				return err
			}
		}
		return check(cs)
	}
	return cfg
}

// HardenTransport installs the distrust check on t's TLS client configuration
// in place and returns t. netsec and the egress guard call it for every
// transport they build; a package outside the crypto boundary can harden a
// transport it already holds without naming crypto/tls.
func HardenTransport(t *http.Transport) *http.Transport {
	if t == nil {
		return nil
	}
	t.TLSClientConfig = HardenTLSConfig(t.TLSClientConfig)
	return t
}
