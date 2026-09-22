// SPDX-License-Identifier: BUSL-1.1

package tlsprobe

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
)

const nativeProbeOutputLimit = 512 << 10

// ProbeWithOpenSSL inventories one direct TLS 1.3 listener using an explicitly
// configured local OpenSSL executable. This supports certificate authentication
// algorithms absent from Go's TLS implementation. The path must come from trusted
// agent startup configuration, never from a job, remote target, or certificate.
// There is no shell, fallback algorithm, application request, or trust assertion.
// As with Probe, callers must independently compare the returned public chain.
// STARTTLS callbacks are refused rather than silently probing a different protocol.
func ProbeWithOpenSSL(ctx context.Context, executable, addr string, opts ...Option) (Result, error) {
	cfg := config{timeout: DefaultTimeout}
	for _, option := range opts {
		option(&cfg)
	}
	if cfg.preHandshake != nil {
		return Result{}, errors.New("tlsprobe: native probe requires direct TLS")
	}
	if !filepath.IsAbs(executable) {
		return Result{}, errors.New("tlsprobe: native executable must be an absolute local path")
	}
	info, err := os.Lstat(executable)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return Result{}, errors.New("tlsprobe: native executable must be a regular executable file")
	}
	host, port, err := net.SplitHostPort(addr)
	n, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || n < 1 || n > 65535 || !nativeProbeToken(host, 253) {
		return Result{}, errors.New("tlsprobe: invalid native probe address")
	}
	if cfg.serverName != "" {
		host = cfg.serverName
	}
	if !nativeProbeToken(host, 253) {
		return Result{}, errors.New("tlsprobe: invalid native probe server name")
	}
	args := []string{"s_client", "-connect", addr, "-servername", host,
		"-tls1_3", "-no_ticket", "-no_ign_eof", "-showcerts", "-brief", "-debug",
		"-nameopt", "RFC2253", "-no-CAfile", "-no-CApath", "-no-CAstore"}
	for _, proto := range cfg.alpn {
		if !nativeProbeToken(proto, 255) || strings.Contains(proto, ",") {
			return Result{}, errors.New("tlsprobe: invalid native ALPN protocol")
		}
	}
	if len(cfg.alpn) != 0 {
		args = append(args, "-alpn", strings.Join(cfg.alpn, ","))
	}
	// OpenSSL's brief success marker is emitted only after SSL_is_init_finished.
	// Debug keeps the public chain output enabled alongside brief mode. All raw
	// output is bounded, read directly into locked memory, never logged, and wiped:
	// verbose OpenSSL output can also contain TLS session material.
	timeout := cfg.timeout
	if timeout <= 0 || timeout > DefaultTimeout {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stdout, err := secret.New(nativeProbeOutputLimit)
	if err != nil {
		return Result{}, errors.New("tlsprobe: cannot protect native probe output")
	}
	defer stdout.Destroy()
	stderr, err := secret.New(nativeProbeOutputLimit)
	if err != nil {
		return Result{}, errors.New("tlsprobe: cannot protect native probe output")
	}
	defer stderr.Destroy()
	outR, outW, err := os.Pipe()
	if err != nil {
		return Result{}, errors.New("tlsprobe: cannot create native output pipe")
	}
	defer func() { _ = outR.Close() }()
	defer func() { _ = outW.Close() }()
	errR, errW, err := os.Pipe()
	if err != nil {
		return Result{}, errors.New("tlsprobe: cannot create native output pipe")
	}
	defer func() { _ = errR.Close() }()
	defer func() { _ = errW.Close() }()
	cmd := exec.CommandContext(ctx, executable, args...) // #nosec G204 -- trusted absolute local executable; fixed verb/options; no shell or remote command.
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "OPENSSL_CONF=/dev/null", "PATH=/usr/bin:/bin"}
	cmd.Stdout, cmd.Stderr = outW, errW
	// A nil stdin is the null device. No application data or interactive commands.
	if err := cmd.Start(); err != nil {
		return Result{}, errors.New("tlsprobe: native probe could not start")
	}
	_ = outW.Close()
	_ = errW.Close()
	stopClosing := context.AfterFunc(ctx, func() { _ = outR.Close(); _ = errR.Close() })
	defer stopClosing()
	type readResult struct {
		n   int
		err error
	}
	outDone, errDone := make(chan readResult, 1), make(chan readResult, 1)
	read := func(file *os.File, dst *secret.Buffer, done chan<- readResult) {
		n, err := readNativeProbeOutput(file, dst.Bytes())
		if err != nil {
			cancel()
		}
		done <- readResult{n, err}
	}
	go read(outR, stdout, outDone)
	go read(errR, stderr, errDone)
	waitErr := cmd.Wait()
	o, e := <-outDone, <-errDone
	if o.err != nil || e.err != nil {
		return Result{}, errors.New("tlsprobe: native probe output was incomplete or exceeded its bound")
	}
	if waitErr != nil || ctx.Err() != nil {
		return Result{}, &StageError{Stage: StageHandshake, Addr: addr, Err: errors.New("native TLS handshake did not complete")}
	}
	return parseNativeProbeOutput(stdout.Bytes()[:o.n], stderr.Bytes()[:e.n], cfg.alpn)
}

func nativeProbeToken(value string, max int) bool {
	if len(value) == 0 || len(value) > max || value[0] == '-' {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] <= ' ' || value[i] >= 127 {
			return false
		}
	}
	return true
}

// Reserve one byte for an overflow sentinel; no io.Copy buffer holds raw output.
func readNativeProbeOutput(reader io.Reader, dst []byte) (int, error) {
	n := 0
	for n < len(dst) {
		count, err := reader.Read(dst[n:])
		n += count
		if n == len(dst) {
			return 0, errors.New("native output bound exceeded")
		}
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			return 0, err
		}
	}
	return 0, errors.New("native output bound exceeded")
}

// parseNativeProbeOutput accepts only the chain printed in OpenSSL's own
// certificate section and a completed TLS 1.3 marker on the separate stderr
// stream. PEM elsewhere (debugging or unsolicited application data) is ignored.
// It never includes raw output in an error or converts it wholesale to string.
func parseNativeProbeOutput(stdout, stderr []byte, offered []string) (Result, error) {
	fail := func() (Result, error) {
		return Result{}, errors.New("tlsprobe: native handshake evidence is incomplete or malformed")
	}
	if len(stdout) >= nativeProbeOutputLimit || len(stderr) >= nativeProbeOutputLimit {
		return fail()
	}
	if countNativeLine(stderr, []byte("CONNECTION ESTABLISHED")) != 1 || countNativeLine(stderr, []byte("Protocol version: TLSv1.3")) != 1 {
		return fail()
	}
	marker := []byte("---\nCertificate chain\n")
	if bytes.Count(stdout, marker) != 1 {
		return fail()
	}
	section := stdout[bytes.Index(stdout, marker)+len(marker):]
	end := bytes.Index(section, []byte("---\nServer certificate\n"))
	if end < 0 {
		return fail()
	}
	chain := section[:end]
	res := Result{TLSVersion: tls.VersionTLS13}
	for {
		begin := bytes.Index(chain, []byte("-----BEGIN CERTIFICATE-----\n"))
		if begin < 0 {
			break
		}
		if begin != 0 && chain[begin-1] != '\n' {
			return fail()
		}
		if bytes.Contains(chain[:begin], []byte("-----BEGIN")) {
			return fail()
		}
		terminator := []byte("-----END CERTIFICATE-----\n")
		finish := bytes.Index(chain[begin:], terminator)
		if finish < 0 {
			return fail()
		}
		finish += begin + len(terminator)
		encoded := chain[begin:finish]
		if bytes.Count(encoded, []byte("-----BEGIN")) != 1 {
			return fail()
		}
		block, trailing := pem.Decode(encoded)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(block.Bytes) > 65536 {
			return fail()
		}
		if len(trailing) != 0 {
			return fail()
		}
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fail()
		}
		if len(res.PeerCertificates) == 0 {
			res.ACMEIdentifier = acmeIdentifierFromCert(parsed)
		}
		res.PeerCertificates = append(res.PeerCertificates, block.Bytes)
		if len(res.PeerCertificates) > 16 {
			return fail()
		}
		chain = chain[finish:]
	}
	if len(res.PeerCertificates) == 0 || bytes.Contains(chain, []byte("-----BEGIN")) {
		return fail()
	}
	// ALPN is read only from the diagnostic footer, not from the peer's name.
	footer := section[end:]
	summaryMarker := []byte("---\nNew, TLSv1.3, Cipher is ")
	startSummary := bytes.Index(footer, summaryMarker)
	if startSummary < 0 {
		return fail()
	}
	footer = footer[startSummary+len(summaryMarker):]
	endSummary := bytes.Index(footer, []byte("\n---\n"))
	if endSummary < 0 {
		return fail()
	}
	footer = footer[:endSummary]
	noALPN := countNativeLine(footer, []byte("No ALPN negotiated"))
	for _, line := range bytes.Split(footer, []byte{'\n'}) {
		if !bytes.HasPrefix(line, []byte("ALPN protocol: ")) {
			continue
		}
		value := line[len("ALPN protocol: "):]
		if res.NegotiatedProtocol != "" {
			return fail()
		}
		matched := false
		for _, offer := range offered {
			if bytes.Equal(value, []byte(offer)) {
				res.NegotiatedProtocol = offer
				matched = true
				break
			}
		}
		if !matched {
			return fail()
		}
	}
	if (res.NegotiatedProtocol == "" && noALPN != 1) || (res.NegotiatedProtocol != "" && noALPN != 0) {
		return fail()
	}
	return res, nil
}

func countNativeLine(data, value []byte) int {
	n := 0
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if bytes.Equal(line, value) {
			n++
		}
	}
	return n
}
