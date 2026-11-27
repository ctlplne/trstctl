// SPDX-License-Identifier: BUSL-1.1

package netsec

import (
	"net"
	"net/netip"
	"sync"
)

// LimitListenerBySource bounds accepted TCP connections for a LAN listener.
// The source is the socket peer IP, never an HTTP header supplied by the client.
// Excess connections are closed immediately so full pools reject fast.
func LimitListenerBySource(base net.Listener, maxTotal, maxPerSource int) net.Listener {
	return &sourceLimitedListener{
		Listener: base,
		maxTotal: maxTotal, maxPerSource: maxPerSource,
		bySource: make(map[string]int),
	}
}

type sourceLimitedListener struct {
	net.Listener
	mu                     sync.Mutex
	maxTotal, maxPerSource int
	total                  int
	bySource               map[string]int
}

func (l *sourceLimitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		source := socketSource(conn.RemoteAddr())
		l.mu.Lock()
		if l.total >= l.maxTotal || l.bySource[source] >= l.maxPerSource {
			l.mu.Unlock()
			_ = conn.Close()
			continue
		}
		l.total++
		l.bySource[source]++
		l.mu.Unlock()
		return &sourceLimitedConn{Conn: conn, release: func() {
			l.mu.Lock()
			l.total--
			l.bySource[source]--
			if l.bySource[source] == 0 {
				delete(l.bySource, source)
			}
			l.mu.Unlock()
		}}, nil
	}
}

func socketSource(remote net.Addr) string {
	if tcp, ok := remote.(*net.TCPAddr); ok {
		if addr, ok := netip.AddrFromSlice(tcp.IP); ok {
			return addr.Unmap().String()
		}
	}
	return remote.Network() + ":" + remote.String()
}

type sourceLimitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *sourceLimitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
