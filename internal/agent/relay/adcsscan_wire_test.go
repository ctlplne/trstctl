// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"

	"trstctl.com/trstctl/internal/discovery/adcs"
)

// TestADCSCollectsEnrollmentACLOverReadOnlyLDAPWireAUD35 is a real LDAP BER
// client/server exchange, not an in-memory Searcher. The fixture accepts exactly
// two SearchRequest operations, inspects the DACL-only control on the template
// query, returns a binary self-relative descriptor, and rejects any third or
// mutating operation. A Windows lab remains necessary for domain policy and
// interoperability, but byte-order/control/attribute behavior is closed here.
func TestADCSCollectsEnrollmentACLOverReadOnlyLDAPWireAUD35(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	conn := ldap.NewConn(clientSide, false)
	conn.SetTimeout(5 * time.Second)
	conn.Start()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- serveReadOnlyADCSLDAPFixture(serverSide)
	}()

	inventory, err := adcs.Collect(context.Background(), ldapSearcher{conn: conn}, "CN=Configuration,DC=corp,DC=example")
	_ = conn.Close()
	if err != nil {
		t.Fatalf("collect AD CS over LDAP wire: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("read-only LDAP fixture: %v", err)
	}
	if len(inventory.Templates) != 1 || inventory.Templates[0].Name != "UserAuth" ||
		!slices.Equal(inventory.Templates[0].EnrollmentPrincipals, []string{"S-1-5-11"}) ||
		!slices.Equal(inventory.Templates[0].PublishedBy, []string{"CORP-CA"}) {
		t.Fatalf("wire inventory lost ACL or publication evidence: %+v", inventory)
	}
}

func serveReadOnlyADCSLDAPFixture(conn net.Conn) error {
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	for index := range 2 {
		request, err := ber.ReadPacket(conn)
		if err != nil {
			return fmt.Errorf("read request %d: %w", index, err)
		}
		if len(request.Children) < 2 || request.Children[1].ClassType != ber.ClassApplication ||
			request.Children[1].Tag != ldap.ApplicationSearchRequest {
			return fmt.Errorf("operation %d is not SearchRequest: class=%d tag=%d", index,
				request.Children[1].ClassType, request.Children[1].Tag)
		}
		search := request.Children[1]
		if len(search.Children) != 8 || search.Children[0].Value == "" {
			return fmt.Errorf("search %d has an invalid bounded request shape", index)
		}
		attributes := ldapWireAttributeNames(search.Children[7])
		if slices.Contains(attributes, "*") {
			return fmt.Errorf("search %d requested a wildcard attribute", index)
		}
		if index == 0 {
			if !slices.Contains(attributes, "nTSecurityDescriptor") {
				return errors.New("template search omitted nTSecurityDescriptor")
			}
			if err := requireWireDACLControl(request); err != nil {
				return err
			}
			if err := writeLDAPSearchResult(conn, request.Children[0].Value,
				"CN=UserAuth,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example",
				map[string][][]byte{
					"cn":                            {[]byte("UserAuth")},
					"displayName":                   {[]byte("User Authentication")},
					"msPKI-Template-Schema-Version": {[]byte("4")},
					"msPKI-Certificate-Name-Flag":   {[]byte("0")},
					"msPKI-Enrollment-Flag":         {[]byte("0")},
					"msPKI-Private-Key-Flag":        {[]byte("0")},
					"pKIExtendedKeyUsage":           {[]byte(adcs.EKUClientAuth)},
					"nTSecurityDescriptor":          {wireEnrollmentDescriptor()},
				}); err != nil {
				return err
			}
			continue
		}
		if len(request.Children) != 2 {
			return errors.New("enrollment-service query unexpectedly carried a control")
		}
		if slices.Contains(attributes, "nTSecurityDescriptor") {
			return errors.New("enrollment-service query requested an unnecessary security descriptor")
		}
		if err := writeLDAPSearchResult(conn, request.Children[0].Value,
			"CN=CORP-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=example",
			map[string][][]byte{
				"cn":                   {[]byte("CORP-CA")},
				"dNSHostName":          {[]byte("ca01.corp.example")},
				"certificateTemplates": {[]byte("UserAuth")},
			}); err != nil {
			return err
		}
	}

	// Collect has no reason to send a third packet. The expected EOF is the
	// client closing after the two searches; any packet here is an undeclared
	// directory operation and fails the fixture.
	packet, err := ber.ReadPacket(conn)
	if err == nil {
		return fmt.Errorf("unexpected third LDAP operation: class=%d tag=%d", packet.Children[1].ClassType, packet.Children[1].Tag)
	}
	if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("wait for read-only client close: %w", err)
	}
	return nil
}

func ldapWireAttributeNames(packet *ber.Packet) []string {
	out := make([]string, 0, len(packet.Children))
	for _, child := range packet.Children {
		if value, ok := child.Value.(string); ok {
			out = append(out, value)
		}
	}
	return out
}

func requireWireDACLControl(request *ber.Packet) error {
	if len(request.Children) != 3 || len(request.Children[2].Children) != 1 {
		return errors.New("template search did not carry exactly one LDAP control")
	}
	control := request.Children[2].Children[0]
	if len(control.Children) != 3 || control.Children[0].Value != ldapServerSDFlagsOID ||
		control.Children[1].Value != true ||
		!slices.Equal(control.Children[2].ByteValue, []byte{0x30, 0x03, 0x02, 0x01, 0x04}) {
		return fmt.Errorf("template search DACL control is wrong: %+v", control.Children)
	}
	return nil
}

func writeLDAPSearchResult(conn net.Conn, messageID any, dn string, attributes map[string][][]byte) error {
	entryEnvelope := ldapWireEnvelope(messageID)
	entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "Search Result Entry")
	entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "Object Name"))
	attributeList := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	for _, name := range sortedLDAPWireKeys(attributes) {
		attribute := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Partial Attribute")
		attribute.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "Attribute Name"))
		values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Attribute Values")
		for _, value := range attributes[name] {
			values.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(value), "Attribute Value"))
		}
		attribute.AppendChild(values)
		attributeList.AppendChild(attribute)
	}
	entry.AppendChild(attributeList)
	entryEnvelope.AppendChild(entry)
	if err := writeLDAPWirePacket(conn, entryEnvelope); err != nil {
		return err
	}

	doneEnvelope := ldapWireEnvelope(messageID)
	done := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultDone, nil, "Search Result Done")
	done.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(ldap.LDAPResultSuccess), "Result Code"))
	done.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Matched DN"))
	done.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Diagnostic Message"))
	doneEnvelope.AppendChild(done)
	return writeLDAPWirePacket(conn, doneEnvelope)
}

func ldapWireEnvelope(messageID any) *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))
	return packet
}

func writeLDAPWirePacket(conn net.Conn, packet *ber.Packet) error {
	encoded := packet.Bytes()
	for len(encoded) > 0 {
		n, err := conn.Write(encoded)
		if err != nil {
			return err
		}
		encoded = encoded[n:]
	}
	return nil
}

func sortedLDAPWireKeys(values map[string][][]byte) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func wireEnrollmentDescriptor() []byte {
	sid := make([]byte, 12)
	sid[0], sid[1], sid[7] = 1, 1, 5
	binary.LittleEndian.PutUint32(sid[8:], 11)
	guid := []byte{0x68, 0xc9, 0x10, 0x0e, 0xfb, 0x78, 0xd2, 0x11, 0x90, 0xd4, 0x00, 0xc0, 0x4f, 0x79, 0xdc, 0x55}
	ace := make([]byte, 12+len(guid)+len(sid))
	ace[0] = 0x05
	binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace))) // #nosec G115 -- this fixed fixture is 40 bytes, below MaxUint16 (CWE-190).
	binary.LittleEndian.PutUint32(ace[4:8], 0x00000100)
	binary.LittleEndian.PutUint32(ace[8:12], 0x1)
	copy(ace[12:], guid)
	copy(ace[12+len(guid):], sid)

	descriptor := make([]byte, 20+8+len(ace))
	descriptor[0] = 1
	binary.LittleEndian.PutUint16(descriptor[2:4], 0x8004)
	binary.LittleEndian.PutUint32(descriptor[16:20], 20)
	acl := descriptor[20:]
	acl[0] = 4
	binary.LittleEndian.PutUint16(acl[2:4], uint16(len(acl))) // #nosec G115 -- this fixed fixture is below MaxUint16 (CWE-190).
	binary.LittleEndian.PutUint16(acl[4:6], 1)
	copy(acl[8:], ace)
	return descriptor
}
