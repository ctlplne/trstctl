// SPDX-License-Identifier: BUSL-1.1

package infratest

// vCenter Server appliance (VMware KB articles on dir-cli and the appliance
// shell; vSphere Automation API reference):
//   - SSH as root with a key to the appliance's bash shell (root's login
//     shell set to /bin/bash, as dir-cli's documentation requires); prompt
//     "root@vcsa [ ~ ]# ".
//   - /usr/lib/vmware-vmafd/bin/dir-cli password reset --account NAME --new
//     'PASSWORD' --login ADMIN@DOMAIN asks "Enter password for ADMIN@DOMAIN:"
//     and answers "Password was reset successfully for [NAME]", or "dir-cli
//     failed. Error 1317 ... ERROR_NO_SUCH_USER" / "Error 49: Invalid
//     credentials".
//   - dir-cli group list --name Administrators --login ADMIN@DOMAIN lists
//     the group's member DNs, CN=NAME,CN=Users,DC=vsphere,DC=local.
//   - REST: POST /api/session with HTTP basic NAME@DOMAIN answers 201 and a
//     session ID (JSON string); a wrong password is 401; DELETE /api/session
//     with vmware-api-session-id ends it.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

type ssoUser struct {
	password []byte
	admin    bool
}

// VCenter is a running appliance stand-in (SSH shell and REST).
type VCenter struct {
	domain      string
	ln          net.Listener
	fingerprint string
	rootKey     []byte
	srv         *httptest.Server

	mu       sync.Mutex
	users    map[string]*ssoUser
	sessions map[string]string
	drop     int
	ran      []string
}

// StartVCenter brings up an appliance whose SSO domain is domain, with the
// SSO administrator "administrator" signing in with adminPassword.
func StartVCenter(domain, adminPassword string) (*VCenter, error) {
	v := &VCenter{domain: domain, users: map[string]*ssoUser{}, sessions: map[string]string{}}
	v.users["administrator"] = &ssoUser{password: []byte(adminPassword), admin: true}
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(signer.PublicKey().Marshal())
	v.fingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	// root's key is ECDSA P-256, a key type the provider's locked signer takes.
	rootPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(rootPriv)
	if err != nil {
		return nil, err
	}
	v.rootKey = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	authorized, err := ssh.NewPublicKey(&rootPriv.PublicKey)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if meta.User() == "root" && bytes.Equal(key.Marshal(), authorized.Marshal()) {
			return &ssh.Permissions{}, nil
		}
		return nil, errors.New("infratest: key refused")
	}}
	cfg.AddHostKey(signer)
	if v.ln, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		return nil, err
	}
	go func() {
		for {
			conn, err := v.ln.Accept()
			if err != nil {
				return
			}
			go v.serveSSH(conn, cfg)
		}
	}()
	v.srv = httptest.NewTLSServer(http.HandlerFunc(v.serveREST))
	return v, nil
}

// AddUser adds an SSO user; admin puts it in the Administrators group.
func (v *VCenter) AddUser(name, password string, admin bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.users[name] = &ssoUser{password: []byte(password), admin: admin}
}

// Password is a user's current password.
func (v *VCenter) Password(name string) []byte {
	v.mu.Lock()
	defer v.mu.Unlock()
	if u, ok := v.users[name]; ok {
		return append([]byte(nil), u.password...)
	}
	return nil
}

// DropNextChanges makes the next n resets report success but keep the old
// password.
func (v *VCenter) DropNextChanges(n int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.drop = n
}

// Sessions counts open REST sessions.
func (v *VCenter) Sessions() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.sessions)
}

// Ran lists the shell command lines run (never a password typed at a prompt).
func (v *VCenter) Ran() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.ran...)
}

// SSHAddr, FingerprintSHA256 and RootKeyPKCS8 are the appliance shell's
// address, pinned host key and root's private key (PKCS#8 PEM).
func (v *VCenter) SSHAddr() string           { return v.ln.Addr().String() }
func (v *VCenter) FingerprintSHA256() string { return v.fingerprint }
func (v *VCenter) RootKeyPKCS8() []byte      { return append([]byte(nil), v.rootKey...) }

// URL, CAPEM and Client are the REST endpoint, its certificate and a client
// trusting only it.
func (v *VCenter) URL() string { return v.srv.URL }
func (v *VCenter) CAPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: v.srv.Certificate().Raw})
}
func (v *VCenter) Client() *http.Client { return v.srv.Client() }

// Close stops both listeners.
func (v *VCenter) Close() {
	_ = v.ln.Close()
	v.srv.Close()
}

// SignsIn reports whether name opens a REST session with password.
func (v *VCenter) SignsIn(name, password string) bool {
	req, _ := http.NewRequest(http.MethodPost, v.srv.URL+"/api/session", nil)
	req.SetBasicAuth(name+"@"+v.domain, password)
	resp, err := v.srv.Client().Do(req)
	if err != nil {
		return false
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return false
	}
	var id string
	if json.Unmarshal(raw, &id) == nil {
		v.mu.Lock()
		delete(v.sessions, id)
		v.mu.Unlock()
	}
	return true
}

func (v *VCenter) check(name string, password []byte) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	u, ok := v.users[name]
	return ok && bytes.Equal(u.password, password)
}

func (v *VCenter) serveREST(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/session" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodPost:
		upn, password, ok := r.BasicAuth()
		name, domain, _ := strings.Cut(upn, "@")
		if !ok || !strings.EqualFold(domain, v.domain) || !v.check(name, []byte(password)) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error_type":"UNAUTHENTICATED","messages":[]}`))
			return
		}
		var raw [16]byte
		_, _ = rand.Read(raw[:])
		id := hex.EncodeToString(raw[:])
		v.mu.Lock()
		v.sessions[id] = name
		v.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(id)
	case http.MethodDelete:
		v.mu.Lock()
		delete(v.sessions, r.Header.Get("vmware-api-session-id"))
		v.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (v *VCenter) serveSSH(conn net.Conn, cfg *ssh.ServerConfig) {
	sconn, channels, requests, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer func() { _ = sconn.Close() }()
	go ssh.DiscardRequests(requests)
	for nc := range channels {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.Prohibited, "sessions only")
			continue
		}
		ch, reqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			for req := range reqs {
				switch req.Type {
				case "pty-req", "env", "window-change":
					_ = req.Reply(true, nil)
				case "shell":
					_ = req.Reply(true, nil)
					go func() {
						v.shell(ch)
						_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
						_ = ch.Close()
					}()
				default:
					_ = req.Reply(false, nil)
				}
			}
		}()
	}
}

const dirCLI = "/usr/lib/vmware-vmafd/bin/dir-cli"

func (v *VCenter) shell(ch io.ReadWriter) {
	write := func(s string) { _, _ = io.WriteString(ch, s) }
	lines := &shellLines{r: ch}
	const prompt = "\r\nroot@vcsa [ ~ ]# "
	write(prompt)
	for {
		line, ok := lines.next()
		if !ok {
			return
		}
		write("\r\n")
		command := strings.TrimSpace(line)
		v.mu.Lock()
		v.ran = append(v.ran, command)
		v.mu.Unlock()
		args, quoted := shellWords(command)
		switch {
		case command == "exit":
			return
		case command == "unset HISTFILE":
		case !quoted:
			write("-bash: syntax error: unterminated quoted string")
		case len(args) >= 1 && args[0] == dirCLI:
			v.dirCLI(args[1:], lines, write)
		default:
			write("-bash: " + args[0] + ": command not found")
		}
		write(prompt)
	}
}

// dirCLI runs the documented subset of dir-cli.
func (v *VCenter) dirCLI(args []string, lines *shellLines, write func(string)) {
	flags := map[string]string{}
	var words []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "--") && i+1 < len(args) {
			flags[args[i]] = args[i+1]
			i++
			continue
		}
		words = append(words, args[i])
	}
	login := flags["--login"]
	if login == "" {
		login = "administrator@" + v.domain
	}
	admin, domain, _ := strings.Cut(login, "@")
	password := []byte(flags["--password"])
	if flags["--password"] == "" {
		write("Enter password for " + login + ": ")
		answer, ok := lines.next()
		if !ok {
			return
		}
		write("\r\n")
		password = []byte(answer)
	}
	v.mu.Lock()
	adminUser, ok := v.users[admin]
	authorized := ok && adminUser.admin && strings.EqualFold(domain, v.domain) && bytes.Equal(adminUser.password, password)
	v.mu.Unlock()
	if !authorized {
		write("dir-cli failed. Error 49: Invalid credentials")
		return
	}
	switch {
	case len(words) == 2 && words[0] == "password" && words[1] == "reset" && flags["--account"] != "" && flags["--new"] != "":
		v.mu.Lock()
		u, ok := v.users[flags["--account"]]
		if ok {
			if v.drop > 0 {
				v.drop--
			} else {
				u.password = []byte(flags["--new"])
			}
		}
		v.mu.Unlock()
		if !ok {
			write("dir-cli failed. Error 1317: Possible errors:\r\n  LDAP error: No such object\r\n  Win Error: ERROR_NO_SUCH_USER")
			return
		}
		write("Password was reset successfully for [" + flags["--account"] + "]")
	case len(words) == 2 && words[0] == "group" && words[1] == "list" && flags["--name"] == "Administrators":
		v.mu.Lock()
		var names []string
		for n, u := range v.users {
			if u.admin {
				names = append(names, n)
			}
		}
		v.mu.Unlock()
		sort.Strings(names)
		dc := "DC=" + strings.ReplaceAll(v.domain, ".", ",DC=")
		for _, n := range names {
			write(fmt.Sprintf("CN=%s,CN=Users,%s\r\n", n, dc))
		}
	default:
		write("dir-cli failed. Error 22: Invalid argument")
	}
}

// shellWords splits a command line as bash would for plain words and
// single-quoted strings; quoted reports a balanced line.
func shellWords(line string) ([]string, bool) {
	var words []string
	var cur strings.Builder
	inQuote, has := false, false
	for _, c := range line {
		switch {
		case c == '\'':
			inQuote, has = !inQuote, true
		case !inQuote && (c == ' ' || c == '\t'):
			if has {
				words = append(words, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(c)
			has = true
		}
	}
	if has {
		words = append(words, cur.String())
	}
	if len(words) == 0 {
		words = []string{""}
	}
	return words, !inQuote
}

type shellLines struct {
	r   io.Reader
	buf []byte
}

func (l *shellLines) next() (string, bool) {
	for {
		if i := bytes.IndexAny(l.buf, "\r\n"); i >= 0 {
			line := string(l.buf[:i])
			l.buf = l.buf[i+1:]
			if line == "" {
				continue
			}
			return line, true
		}
		chunk := make([]byte, 512)
		n, err := l.r.Read(chunk)
		l.buf = append(l.buf, chunk[:n]...)
		if err != nil && n == 0 {
			return "", false
		}
	}
}
