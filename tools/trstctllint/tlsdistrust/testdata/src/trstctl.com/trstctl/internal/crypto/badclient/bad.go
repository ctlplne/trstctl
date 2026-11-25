package badclient

import (
	"crypto/tls"
	"net"
	"net/http"
)

func bad(conn net.Conn) {
	_ = tls.Client(conn, &tls.Config{})   // want "direct crypto/tls client bypasses the runtime distrust list"
	_ = tls.Dialer{Config: &tls.Config{}} // want "direct crypto/tls.Dialer bypasses the runtime distrust list"
	_ = new(tls.Dialer)                   // want "direct crypto/tls.Dialer bypasses the runtime distrust list"
	var dialer tls.Dialer                 // want "direct crypto/tls.Dialer bypasses the runtime distrust list"
	_ = dialer
	_, _ = tls.Dial("tcp", "localhost:443", &tls.Config{})       // want "direct crypto/tls client bypasses the runtime distrust list"
	transport := &http.Transport{TLSClientConfig: &tls.Config{}} // want "direct HTTP TLSClientConfig override bypasses the runtime distrust list"
	transport.TLSClientConfig = &tls.Config{}                    // want "direct HTTP TLSClientConfig override bypasses the runtime distrust list"
}
