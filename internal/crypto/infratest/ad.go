// SPDX-License-Identifier: BUSL-1.1

package infratest

// Active Directory stand-in (A258-L1): LDAPS on loopback speaking the part of
// RFC 4511 a directory account's sign-in check uses — simple binds, base-object
// searches, unbind — with Active Directory's account semantics from
// Microsoft's documentation (MS-ADTS, the user attribute references and the
// LDAP error reference):
//
//   - A bind with a wrong password answers invalidCredentials (49) with the
//     diagnostic "AcceptSecurityContext error, data 52e" and adds one to the
//     account's badPwdCount; reaching the lockout threshold that applies to the
//     account — its resultant password settings object's
//     msDS-LockoutThreshold, else the domain's lockoutThreshold, 0 being never
//     — locks it. A locked account answers data 775 and counts nothing; a
//     disabled one 533; with the right password, an expired account 701, a
//     password that must change 773; a right password resets the count.
//   - A search needs a bound connection (operationsError otherwise) and
//     returns the requested attributes of the base object: the RootDSE's
//     defaultNamingContext, the domain's lockoutThreshold, a password settings
//     object's msDS-LockoutThreshold (none when it is unreadable), and an
//     account's sAMAccountName, userAccountControl (512, plus 2 disabled),
//     msDS-User-Account-Control-Computed (16 locked, 0x800000 password
//     expired), badPwdCount, pwdLastSet (0 must change), accountExpires and
//     msDS-ResultantPSO.

import (
	"bufio"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"

	"trstctl.com/trstctl/internal/crypto/mtls"
)

// ADServerName is the name the stand-in's certificate carries.
const ADServerName = "ad.test"

type adAccount struct {
	dn, name   string
	password   []byte
	bad        int
	locked     bool
	disabled   bool
	mustChange bool
	expired    bool
	pso        string
	signIns    int
}

// AD is a running Active Directory stand-in.
type AD struct {
	ln     net.Listener
	cert   *mtls.ServerCert
	domain string

	mu          sync.Mutex
	threshold   int
	admins      map[string][]byte
	accounts    map[string]*adAccount
	psos        map[string]int
	psoHidden   bool
	open        map[net.Conn]bool
	connections sync.WaitGroup
}

// StartAD is a domain dc=... with lockoutThreshold threshold whose
// administrator adminDN signs in with adminPassword.
func StartAD(domainDN string, threshold int, adminDN string, adminPassword []byte) (*AD, error) {
	cert, err := mtls.SelfSignedServerCert([]string{ADServerName, "127.0.0.1"}, time.Hour)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	d := &AD{ln: cert.Listener(ln), cert: cert, domain: domainDN, threshold: threshold,
		admins:   map[string][]byte{strings.ToLower(adminDN): append([]byte(nil), adminPassword...)},
		accounts: map[string]*adAccount{}, psos: map[string]int{}, open: map[net.Conn]bool{}}
	go d.accept()
	return d, nil
}

// Addr is the LDAPS listener's host:port.
func (d *AD) Addr() string { return d.ln.Addr().String() }

// CAPEM is the stand-in's self-signed certificate.
func (d *AD) CAPEM() []byte { return append([]byte(nil), d.cert.TrustPEM...) }

// Close stops the stand-in and ends its connections.
func (d *AD) Close() {
	_ = d.ln.Close()
	d.mu.Lock()
	for conn := range d.open {
		_ = conn.Close()
	}
	d.mu.Unlock()
	d.connections.Wait()
}

// AddAccount adds a user account dn (sAMAccountName name) with password.
func (d *AD) AddAccount(dn, name string, password []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.accounts[strings.ToLower(dn)] = &adAccount{dn: dn, name: name, password: append([]byte(nil), password...)}
}

// SetPassword changes an account's password, as an administrator elsewhere
// would.
func (d *AD) SetPassword(dn string, password []byte) {
	d.with(dn, func(a *adAccount) { a.password = append([]byte(nil), password...) })
}

// SetBadPwdCount sets an account's failed sign-ins, as someone else's wrong
// passwords would.
func (d *AD) SetBadPwdCount(dn string, n int) { d.with(dn, func(a *adAccount) { a.bad = n }) }

// Disable disables an account; MustChange makes its password one that must
// change; Expire makes the account expired; Unlock unlocks it and clears its
// count, as an administrator would.
func (d *AD) Disable(dn string)    { d.with(dn, func(a *adAccount) { a.disabled = true }) }
func (d *AD) MustChange(dn string) { d.with(dn, func(a *adAccount) { a.mustChange = true }) }
func (d *AD) Expire(dn string)     { d.with(dn, func(a *adAccount) { a.expired = true }) }
func (d *AD) Unlock(dn string)     { d.with(dn, func(a *adAccount) { a.locked, a.bad = false, 0 }) }

// Lock locks an account, as enough wrong passwords elsewhere would.
func (d *AD) Lock(dn string) { d.with(dn, func(a *adAccount) { a.locked = true }) }

// SetLockoutThreshold changes the domain's lockoutThreshold (0 never locks).
func (d *AD) SetLockoutThreshold(n int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.threshold = n
}

// ApplyPSO creates the password settings object pso with lockout threshold
// threshold and makes it the account's resultant one.
func (d *AD) ApplyPSO(accountDN, pso string, threshold int) {
	d.mu.Lock()
	d.psos[strings.ToLower(pso)] = threshold
	d.mu.Unlock()
	d.with(accountDN, func(a *adAccount) { a.pso = pso })
}

// HidePSOs makes password settings objects unreadable, as they are to an
// administrator outside Domain Admins by default.
func (d *AD) HidePSOs() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.psoHidden = true
}

// BadPwdCount, Locked and SignIns read an account: its failed sign-ins, its
// lockout, and every bind attempted as it.
func (d *AD) BadPwdCount(dn string) (n int) { d.with(dn, func(a *adAccount) { n = a.bad }); return n }
func (d *AD) Locked(dn string) (l bool)     { d.with(dn, func(a *adAccount) { l = a.locked }); return l }
func (d *AD) SignIns(dn string) (n int)     { d.with(dn, func(a *adAccount) { n = a.signIns }); return n }

func (d *AD) with(dn string, f func(*adAccount)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if a := d.accounts[strings.ToLower(dn)]; a != nil {
		f(a)
	}
}

func (d *AD) accept() {
	for {
		conn, err := d.ln.Accept()
		if err != nil {
			return
		}
		d.mu.Lock()
		d.open[conn] = true
		d.mu.Unlock()
		d.connections.Add(1)
		go func() {
			defer d.connections.Done()
			defer func() {
				d.mu.Lock()
				delete(d.open, conn)
				d.mu.Unlock()
				_ = conn.Close()
			}()
			_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
			d.serve(conn)
		}()
	}
}

const (
	adResultSuccess            = 0
	adResultOperationsError    = 1
	adResultProtocolError      = 2
	adResultNoSuchObject       = 32
	adResultInvalidCredentials = 49
)

func (d *AD) serve(conn net.Conn) {
	reader := bufio.NewReader(conn)
	bound := false
	for {
		packet, err := ber.ReadPacket(reader)
		if err != nil || len(packet.Children) < 2 {
			return
		}
		id, ok := packet.Children[0].Value.(int64)
		if !ok {
			return
		}
		op := packet.Children[1]
		switch op.Tag {
		case 0: // BindRequest
			code, diagnostic := d.bind(op)
			bound = code == adResultSuccess
			if !write(conn, id, adResult(1, code, diagnostic)) {
				return
			}
		case 2: // UnbindRequest
			return
		case 3: // SearchRequest
			if !bound {
				if !write(conn, id, adResult(5, adResultOperationsError, "000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563")) {
					return
				}
				continue
			}
			entry, code := d.search(op)
			if entry != nil && !write(conn, id, entry) {
				return
			}
			if !write(conn, id, adResult(5, code, "")) {
				return
			}
		default:
			if !write(conn, id, adResult(1, adResultProtocolError, "")) {
				return
			}
		}
	}
}

func (d *AD) bind(op *ber.Packet) (int64, string) {
	if len(op.Children) < 3 || op.Children[2].Tag != 0 {
		return adResultProtocolError, ""
	}
	name, _ := op.Children[1].Value.(string)
	password := op.Children[2].Data.Bytes()
	refused := func(sub string) (int64, string) {
		return adResultInvalidCredentials, "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data " + sub + ", v4563"
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	key := strings.ToLower(name)
	if admin, ok := d.admins[key]; ok {
		if string(admin) != string(password) {
			return refused("52e")
		}
		return adResultSuccess, ""
	}
	a := d.accounts[key]
	if a == nil {
		return refused("52e")
	}
	a.signIns++
	switch {
	case a.locked:
		return refused("775")
	case string(a.password) != string(password):
		if !a.disabled {
			a.bad++
			if t := d.thresholdOf(a); t > 0 && a.bad >= t {
				a.locked = true
			}
		}
		return refused("52e")
	case a.disabled:
		return refused("533")
	case a.expired:
		return refused("701")
	case a.mustChange:
		return refused("773")
	}
	a.bad = 0
	return adResultSuccess, ""
}

func (d *AD) thresholdOf(a *adAccount) int {
	if a.pso != "" {
		return d.psos[strings.ToLower(a.pso)]
	}
	return d.threshold
}

func (d *AD) search(op *ber.Packet) (*ber.Packet, int64) {
	if len(op.Children) < 8 {
		return nil, adResultProtocolError
	}
	base, _ := op.Children[0].Value.(string)
	wanted := map[string]bool{}
	for _, attr := range op.Children[7].Children {
		if name, ok := attr.Value.(string); ok {
			wanted[strings.ToLower(name)] = true
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	values := map[string]string{}
	key := strings.ToLower(base)
	threshold, pso := d.psos[key]
	switch {
	case base == "":
		values["defaultNamingContext"] = d.domain
	case key == strings.ToLower(d.domain):
		values["lockoutThreshold"] = strconv.Itoa(d.threshold)
	case pso:
		if !d.psoHidden {
			values["msDS-LockoutThreshold"] = strconv.Itoa(threshold)
		}
	default:
		a := d.accounts[key]
		if a == nil {
			return nil, adResultNoSuchObject
		}
		uac, computed := 512, 0
		if a.disabled {
			uac |= 2
		}
		if a.locked {
			computed |= 16
		}
		pwdLastSet, expires := "133000000000000000", "9223372036854775807"
		if a.mustChange {
			pwdLastSet = "0"
		}
		if a.expired {
			expires = "132000000000000000"
		}
		values["sAMAccountName"] = a.name
		values["userAccountControl"] = strconv.Itoa(uac)
		values["msDS-User-Account-Control-Computed"] = strconv.Itoa(computed)
		values["badPwdCount"] = strconv.Itoa(a.bad)
		values["pwdLastSet"] = pwdLastSet
		values["accountExpires"] = expires
		if a.pso != "" {
			values["msDS-ResultantPSO"] = a.pso
		}
	}
	entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "SearchResultEntry")
	entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, base, "objectName"))
	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for name, value := range values {
		if len(wanted) > 0 && !wanted[strings.ToLower(name)] {
			continue
		}
		attribute := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attribute")
		attribute.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "type"))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
		set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "value"))
		attribute.AppendChild(set)
		attributes.AppendChild(attribute)
	}
	entry.AppendChild(attributes)
	return entry, adResultSuccess
}

func adResult(tag ber.Tag, code int64, diagnostic string) *ber.Packet {
	result := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "LDAPResult")
	result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "resultCode"))
	result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diagnostic, "diagnosticMessage"))
	return result
}

func write(conn net.Conn, id int64, op *ber.Packet) bool {
	message := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	message.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "messageID"))
	message.AppendChild(op)
	_, err := conn.Write(message.Bytes())
	return err == nil
}
