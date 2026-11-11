// SPDX-License-Identifier: BUSL-1.1

// Package netdevicetest is a stand-in network device for tests (A270): an SSH
// server with password and keyboard-interactive sign-in against its own
// account table, speaking the documented subset of a vendor's CLI that account
// rotation and discovery use. It lives in the crypto boundary because it
// generates its SSH host key.
//
// IOS-XE (Cisco IOS XE configuration guides): privileged EXEC "#", user EXEC
// ">", `configure terminal`, `username NAME [privilege N] secret 0 PASSWORD`,
// `enable secret 0 PASSWORD`, `end`, `write memory`, `disable`, `enable`,
// `terminal length 0`, `show running-config | include ^username`.
// Junos (Junos OS CLI user guide): operational ">", configuration "#",
// `set cli screen-length 0`, `configure private`, `set system login user NAME
// authentication plain-text-password` (asks "New password:" twice),
// `set system login user NAME class CLASS`, `commit and-quit`, `rollback 0`,
// `exit configuration-mode`, `show configuration system login | display set`.
// EOS, FortiOS and BIG-IP (tmsh) over SSH are the command line a brokered
// session uses: each vendor's prompt, its version command (`show version`,
// `get system status`, `show sys version`) and save command, every other
// line accepted. Every dialect runs an exec request's command as one line
// and logs each command line it runs (Ran).
package netdevicetest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

// Dialect is a vendor CLI.
type Dialect string

const (
	IOSXE Dialect = "ios-xe"
	Junos Dialect = "junos"
)

type account struct {
	password []byte
	role     string
}

// Device is a running stand-in.
type Device struct {
	dialect     Dialect
	ln          net.Listener
	fingerprint string

	mu       sync.Mutex
	accounts map[string]*account
	enable   []byte
	changed  map[string]bool
	reject   bool
	drop     int
	writes   int
	ran      []string
}

// Start brings up a stand-in of dialect with one administrator.
func Start(dialect Dialect, admin, password, role string) (*Device, error) {
	switch dialect {
	case IOSXE, Junos, EOS, FortiOS, BIGIP:
	default:
		return nil, errors.New("netdevicetest: unknown dialect")
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(signer.PublicKey().Marshal())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	d := &Device{dialect: dialect, ln: ln, fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]),
		accounts: map[string]*account{}, changed: map[string]bool{}}
	d.AddAccount(admin, password, role)
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			return d.authenticate(meta.User(), pw)
		},
		KeyboardInteractiveCallback: func(meta ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, err := challenge("", "", []string{"Password: "}, []bool{false})
			if err != nil || len(answers) != 1 {
				return nil, errors.New("netdevicetest: no answer")
			}
			return d.authenticate(meta.User(), []byte(answers[0]))
		},
	}
	cfg.AddHostKey(signer)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go d.serve(conn, cfg)
		}
	}()
	return d, nil
}

func (d *Device) authenticate(user string, pw []byte) (*ssh.Permissions, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	a, ok := d.accounts[user]
	if !ok || !bytes.Equal(a.password, pw) || (d.reject && d.changed[user]) {
		return nil, errors.New("netdevicetest: authentication failed")
	}
	return &ssh.Permissions{}, nil
}

// AddAccount sets an account's password and role (privilege or login class).
func (d *Device) AddAccount(name, password, role string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.accounts[name] = &account{password: []byte(password), role: role}
}

// SetEnableSecret sets the IOS-XE privileged-mode secret.
func (d *Device) SetEnableSecret(secret string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.enable = []byte(secret)
}

// Password returns an account's current password (nil when it has none).
func (d *Device) Password(name string) []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	if a, ok := d.accounts[name]; ok {
		return append([]byte(nil), a.password...)
	}
	return nil
}

// EnableSecret returns the privileged-mode secret.
func (d *Device) EnableSecret() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]byte(nil), d.enable...)
}

// Role returns an account's privilege or class.
func (d *Device) Role(name string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if a, ok := d.accounts[name]; ok {
		return a.role
	}
	return ""
}

// RejectChangedPasswords makes every password changed from now on refuse
// sign-in, as a device whose change did not take effect: rollback proofs.
func (d *Device) RejectChangedPasswords(reject bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.reject = reject
	if !reject {
		d.changed = map[string]bool{}
	}
}

// DropNextChanges makes the next n password changes report success but
// leave the old password in place, as a device whose change did not take
// effect: the rotation's own verification then fails and rolls back.
func (d *Device) DropNextChanges(n int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.drop = n
}

// Writes counts saved configurations (IOS-XE write memory, Junos commit).
func (d *Device) Writes() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.writes
}

// Ran lists the command lines the device ran, in order (shell and exec;
// never a password typed at a prompt).
func (d *Device) Ran() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.ran...)
}

func (d *Device) record(line string) {
	d.mu.Lock()
	d.ran = append(d.ran, line)
	d.mu.Unlock()
}

func (d *Device) Addr() string              { return d.ln.Addr().String() }
func (d *Device) FingerprintSHA256() string { return d.fingerprint }
func (d *Device) Close()                    { _ = d.ln.Close() }

func (d *Device) serve(conn net.Conn, cfg *ssh.ServerConfig) {
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
						d.shell(ch, sconn.User())
						_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
						_ = ch.Close()
					}()
				case "exec":
					// A device runs one exec command as if typed at a fresh
					// session's prompt, then ends the channel.
					var command struct{ Line string }
					if ssh.Unmarshal(req.Payload, &command) != nil {
						_ = req.Reply(false, nil)
						continue
					}
					_ = req.Reply(true, nil)
					go func() {
						d.run(&lineReader{r: strings.NewReader(command.Line + "\n")}, func(s string) { _, _ = io.WriteString(ch, s) }, sconn.User())
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

// shell runs one CLI session for user.
func (d *Device) shell(ch io.ReadWriter, user string) {
	write := func(s string) { _, _ = io.WriteString(ch, s) }
	// A device echoes the end of each typed line, so output starts on a line
	// of its own after the prompt.
	lines := lineReader{r: ch, echo: func() { write("\r\n") }}
	d.run(&lines, write, user)
}

func (d *Device) run(lines *lineReader, write func(string), user string) {
	switch d.dialect {
	case IOSXE:
		d.iosxe(lines, write)
	case Junos:
		d.junos(lines, write, user)
	default:
		d.generic(lines, write, user)
	}
}

// generic is the EOS, FortiOS and BIG-IP (tmsh) command line a brokered
// session uses: each vendor's prompt, its version command, its save command,
// and every other line accepted and logged.
func (d *Device) generic(lines *lineReader, write func(string), user string) {
	prompt := map[Dialect]string{EOS: "\r\nswitch#", FortiOS: "\r\nFGT # ", BIGIP: "\r\n" + user + "@(bigip)(cfg-sync Standalone)(Active)(/Common)(tmos)# "}[d.dialect]
	write(prompt)
	for {
		line, ok := lines.next()
		if !ok {
			return
		}
		switch line = strings.TrimSpace(line); {
		case line == "exit" || line == "quit" || line == "logout":
			return
		case d.dialect == EOS && line == "show version":
			write("Arista vEOS-lab\r\nSoftware image version: 4.32.0F")
		case d.dialect == FortiOS && line == "get system status":
			write("Version: FortiGate-VM64 v7.4.4,build2662,240514 (GA.F)\r\nHostname: FGT")
		case d.dialect == BIGIP && line == "show sys version":
			write("Sys::Version\r\nMain Package\r\n  Product     BIG-IP\r\n  Version     17.1.1")
		case (d.dialect == EOS && (line == "write memory" || line == "copy running-config startup-config")) ||
			(d.dialect == BIGIP && line == "save sys config"):
			d.mu.Lock()
			d.writes++
			d.mu.Unlock()
			write("Copy completed successfully.")
		default:
			write("% ok")
		}
		d.record(line)
		write(prompt)
	}
}

// lineReader is a device's command-line editor: it builds each line from the
// keys typed, applying the editing keys every vendor's editor shares — erase
// (Backspace, Delete), kill line (Ctrl-U, and Ctrl-C, which abandons it) and
// erase word (Ctrl-W) — and runs it on Enter.
type lineReader struct {
	r    io.Reader
	buf  []byte
	line []byte
	echo func()
}

func (l *lineReader) next() (string, bool) {
	for {
		for len(l.buf) > 0 {
			b := l.buf[0]
			l.buf = l.buf[1:]
			switch b {
			case '\r', '\n':
				line := string(l.line)
				l.line = l.line[:0]
				if line == "" {
					continue
				}
				if l.echo != nil {
					l.echo()
				}
				return line, true
			case 0x08, 0x7f:
				if len(l.line) > 0 {
					_, size := utf8.DecodeLastRune(l.line)
					l.line = l.line[:len(l.line)-size]
				}
			case 0x15, 0x03:
				l.line = l.line[:0]
			case 0x17:
				end := len(l.line)
				for end > 0 && l.line[end-1] == ' ' {
					end--
				}
				for end > 0 && l.line[end-1] != ' ' {
					end--
				}
				l.line = l.line[:end]
			default:
				l.line = append(l.line, b)
			}
		}
		chunk := make([]byte, 512)
		n, err := l.r.Read(chunk)
		l.buf = append(l.buf, chunk[:n]...)
		if err != nil && n == 0 {
			return "", false
		}
	}
}

func (d *Device) setPassword(name string, pw []byte, role string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	a, ok := d.accounts[name]
	if !ok {
		a = &account{role: role}
		d.accounts[name] = a
	}
	if role != "" {
		a.role = role
	}
	if d.drop > 0 {
		d.drop--
		return
	}
	a.password = append([]byte(nil), pw...)
	d.changed[name] = true
}

func (d *Device) iosxe(lines *lineReader, write func(string)) {
	mode := "#"
	prompt := func() {
		write(map[string]string{"#": "\r\nrouter#", ">": "\r\nrouter>", "config": "\r\nrouter(config)#"}[mode])
	}
	prompt()
	for {
		line, ok := lines.next()
		if !ok {
			return
		}
		d.record(line)
		f := strings.Fields(line)
		switch {
		case mode != "config" && line == "terminal length 0":
		case mode == "#" && line == "configure terminal":
			write("Enter configuration commands, one per line.  End with CNTL/Z.")
			mode = "config"
		case mode == "config" && (line == "end" || line == "exit"):
			mode = "#"
		case mode == "config" && len(f) >= 5 && f[0] == "username" && f[len(f)-3] == "secret" && f[len(f)-2] == "0":
			role := ""
			if len(f) == 7 && f[2] == "privilege" {
				role = "privilege " + f[3]
			} else if len(f) != 5 {
				write("% Invalid input detected at '^' marker.")
				break
			} else {
				// IOS replaces the whole username line: no privilege is privilege 1.
				role = "privilege 1"
			}
			d.setPassword(f[1], []byte(f[len(f)-1]), role)
		case mode == "config" && len(f) == 4 && f[0] == "enable" && f[1] == "secret" && f[2] == "0":
			d.mu.Lock()
			d.enable = []byte(f[3])
			d.changed["enable"] = true
			d.mu.Unlock()
		case mode == "#" && line == "write memory":
			d.mu.Lock()
			d.writes++
			d.mu.Unlock()
			write("Building configuration...\r\n[OK]")
		case mode == "#" && line == "show running-config | include ^username":
			d.mu.Lock()
			names := make([]string, 0, len(d.accounts))
			for n := range d.accounts {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				sum := sha256.Sum256(d.accounts[n].password)
				write(fmt.Sprintf("username %s %s secret 9 $9$%s\r\n", n, d.accounts[n].role, base64.RawStdEncoding.EncodeToString(sum[:12])))
			}
			d.mu.Unlock()
		case mode == "#" && line == "disable":
			mode = ">"
		case mode == ">" && line == "enable":
			write("Password: ")
			secret, ok := lines.next()
			if !ok {
				return
			}
			d.mu.Lock()
			good := len(d.enable) > 0 && secret == string(d.enable) && (!d.reject || !d.changed["enable"])
			d.mu.Unlock()
			if good {
				mode = "#"
			} else {
				write("% Access denied")
			}
		case line == "exit" || line == "logout":
			return
		default:
			write("% Invalid input detected at '^' marker.")
		}
		prompt()
	}
}

func (d *Device) junos(lines *lineReader, write func(string), user string) {
	config := false
	pending := map[string][]byte{}
	classes := map[string]string{}
	prompt := func() {
		if config {
			write("\r\n[edit]\r\n" + user + "@junos-standin# ")
		} else {
			write("\r\n" + user + "@junos-standin> ")
		}
	}
	prompt()
	for {
		line, ok := lines.next()
		if !ok {
			return
		}
		d.record(line)
		f := strings.Fields(line)
		switch {
		case !config && line == "set cli screen-length 0":
			write("Screen length set to 0")
		case !config && line == "configure private":
			write("warning: uncommitted changes will be discarded on exit\r\nEntering configuration mode")
			config = true
		case config && len(f) == 7 && f[0] == "set" && f[1] == "system" && f[2] == "login" && f[3] == "user" && f[5] == "authentication" && f[6] == "plain-text-password":
			write("New password:")
			first, ok := lines.next()
			if !ok {
				return
			}
			write("\r\nRetype new password:")
			second, ok := lines.next()
			if !ok {
				return
			}
			if first != second {
				write("\r\nerror: passwords do not match")
				break
			}
			pending[f[4]] = []byte(first)
		case config && len(f) == 7 && f[0] == "set" && f[1] == "system" && f[2] == "login" && f[3] == "user" && f[5] == "class":
			classes[f[4]] = f[6]
		case config && line == "commit and-quit":
			for name, pw := range pending {
				d.setPassword(name, pw, classes[name])
			}
			d.mu.Lock()
			for name, class := range classes {
				if a, ok := d.accounts[name]; ok && pending[name] == nil {
					a.role = class
				}
			}
			d.writes++
			d.mu.Unlock()
			pending, classes = map[string][]byte{}, map[string]string{}
			write("commit complete\r\nExiting configuration mode")
			config = false
		case config && (line == "rollback 0" || line == "exit configuration-mode"):
			pending, classes = map[string][]byte{}, map[string]string{}
			config = line == "rollback 0"
		case !config && line == "show configuration system login | display set":
			d.mu.Lock()
			names := make([]string, 0, len(d.accounts))
			for n := range d.accounts {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				sum := sha256.Sum256(d.accounts[n].password)
				write(fmt.Sprintf("set system login user %s class %s\r\nset system login user %s authentication encrypted-password \"$6$%s\"\r\n",
					n, d.accounts[n].role, n, base64.RawStdEncoding.EncodeToString(sum[:12])))
			}
			d.mu.Unlock()
		case line == "exit" || line == "quit":
			return
		default:
			write("syntax error.")
		}
		prompt()
	}
}
