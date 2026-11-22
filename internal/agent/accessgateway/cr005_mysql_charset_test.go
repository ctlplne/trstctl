// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/mysqlsignin"
)

func TestCR005GuardedMySQLRefusesGBKBeforeUpstreamSignIn(t *testing.T) {
	client, gatewaySide := net.Pipe()
	upstream, serverSide := net.Pipe()
	defer func() { _ = client.Close(); _ = gatewaySide.Close(); _ = upstream.Close(); _ = serverSide.Close() }()
	deadline := time.Now().Add(5 * time.Second)
	for _, conn := range []net.Conn{client, gatewaySide, upstream, serverSide} {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}
	upstreamSignedIn := make(chan bool, 1)
	go func() {
		defer func() { _ = serverSide.Close() }()
		greeting, err := mysqlsignin.ClientHandshake(&mysqlsignin.Handshake{
			ServerVersion: "8.4.10", ConnectionID: 42, Capabilities: 0xdfffffff,
			Charset: 255, Status: 2, AuthPlugin: "caching_sha2_password", Scramble: bytes.Repeat([]byte{'s'}, 20),
		})
		if err != nil || mysqlsignin.WritePacket(serverSide, 0, greeting) != nil {
			upstreamSignedIn <- false
			return
		}
		_, _, err = mysqlsignin.ReadPacket(serverSide)
		upstreamSignedIn <- err == nil
	}()
	served := make(chan error, 1)
	go func() {
		served <- serveMySQL(context.Background(), gatewaySide, []byte("fixture:fixture@tcp(127.0.0.1:3306)/app"), deadline,
			func(context.Context, string, string) (net.Conn, error) { return upstream, nil }, "", nil, &commandConnection{})
	}()
	if _, _, err := mysqlsignin.ReadPacket(client); err != nil {
		t.Fatalf("gateway greeting: %v", err)
	}
	const caps = mysqlsignin.ClientProtocol41 | mysqlsignin.ClientSecureConnection | mysqlsignin.ClientPluginAuth | mysqlsignin.ClientPluginAuthLenencClientData
	response := binary.LittleEndian.AppendUint32(nil, caps)
	response = binary.LittleEndian.AppendUint32(response, 1<<24)
	response = append(response, 28) // gbk_chinese_ci: 0x5c may be a multibyte trail byte.
	response = append(response, make([]byte, 23)...)
	response = append(response, "fixture\x00"...)
	response = append(response, 0) // empty lenenc auth answer
	response = append(response, "caching_sha2_password\x00"...)
	if err := mysqlsignin.WritePacket(client, 1, response); err != nil {
		t.Fatal(err)
	}
	_, refusal, readErr := mysqlsignin.ReadPacket(client)
	_ = client.Close()
	if err := <-served; err == nil {
		t.Error("GBK handshake unexpectedly completed")
	}
	if signedIn := <-upstreamSignedIn; signedIn {
		t.Error("gateway forwarded a GBK charset to upstream authentication before reviewing commands")
	}
	if readErr != nil || len(refusal) == 0 || refusal[0] != 0xff || !strings.Contains(string(refusal), "supported SQL connection charset") {
		t.Errorf("guarded GBK handshake = %x, %v; want a clear MySQL refusal before upstream sign-in", refusal, readErr)
	}
}
