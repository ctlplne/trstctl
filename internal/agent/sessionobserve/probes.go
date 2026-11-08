// SPDX-License-Identifier: BUSL-1.1

package sessionobserve

// probe is one attachment: a program on a library function's entry or return.
type probe struct {
	crypto  bool
	symbol  string
	program string
	ret     bool
}

var probes = []probe{
	{symbol: "SSL_set0_rbio", program: "set_rbio"},
	{symbol: "SSL_set0_wbio", program: "set_wbio"},
	{symbol: "SSL_free", program: "ssl_free"},
	{symbol: "SSL_clear", program: "ssl_clear"},
	{symbol: "SSL_do_handshake", program: "handshake_enter"},
	{symbol: "SSL_do_handshake", program: "handshake_exit", ret: true},
	{symbol: "SSL_connect", program: "handshake_enter"},
	{symbol: "SSL_connect", program: "handshake_exit", ret: true},
	{symbol: "SSL_accept", program: "handshake_enter"},
	{symbol: "SSL_accept", program: "handshake_exit", ret: true},
	{symbol: "SSL_read", program: "io_call_enter"},
	{symbol: "SSL_read", program: "io_call_exit", ret: true},
	{symbol: "SSL_write", program: "io_call_enter"},
	{symbol: "SSL_write", program: "io_call_exit", ret: true},
	{symbol: "SSL_read_ex", program: "io_call_enter"},
	{symbol: "SSL_read_ex", program: "io_call_exit", ret: true},
	{symbol: "SSL_write_ex", program: "io_call_enter"},
	{symbol: "SSL_write_ex", program: "io_call_exit", ret: true},
	{crypto: true, symbol: "d2i_X509", program: "certificate"},
	{crypto: true, symbol: "BIO_read", program: "bio_read_enter"},
	{crypto: true, symbol: "BIO_read", program: "bio_read_exit", ret: true},
	{crypto: true, symbol: "BIO_write", program: "bio_write_enter"},
	{crypto: true, symbol: "BIO_write", program: "bio_write_exit", ret: true},
	{crypto: true, symbol: "BIO_write_ex", program: "bio_write_ex_enter"},
	{crypto: true, symbol: "BIO_write_ex", program: "bio_write_ex_exit", ret: true},
}
