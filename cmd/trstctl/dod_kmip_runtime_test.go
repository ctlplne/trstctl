//go:build trstctl_dodproof

// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/tools/dodcensus/proof"
)

const (
	dodKMIPEntryID = "secrets_residuals.kmip_wrapping_profile_negotiation"

	dodTTLVStructure   byte = 0x01
	dodTTLVInteger     byte = 0x02
	dodTTLVEnumeration byte = 0x05
	dodTTLVText        byte = 0x07
	dodTTLVBytes       byte = 0x08

	dodTagBatchCount               uint32 = 0x42000d
	dodTagBatchItem                uint32 = 0x42000f
	dodTagBlockCipherMode          uint32 = 0x420011
	dodTagCryptographicAlgorithm   uint32 = 0x420028
	dodTagCryptographicLength      uint32 = 0x42002a
	dodTagCryptographicParameters  uint32 = 0x42002b
	dodTagEncryptionKeyInformation uint32 = 0x420036
	dodTagIVCounterNonce           uint32 = 0x42003d
	dodTagKeyBlock                 uint32 = 0x420040
	dodTagKeyFormatType            uint32 = 0x420042
	dodTagKeyMaterial              uint32 = 0x420043
	dodTagKeyValue                 uint32 = 0x420045
	dodTagKeyWrappingData          uint32 = 0x420046
	dodTagKeyWrappingSpecification uint32 = 0x420047
	dodTagMACSignature             uint32 = 0x42004d
	dodTagObjectType               uint32 = 0x420057
	dodTagOperation                uint32 = 0x42005c
	dodTagProtocolVersion          uint32 = 0x420069
	dodTagProtocolVersionMajor     uint32 = 0x42006a
	dodTagProtocolVersionMinor     uint32 = 0x42006b
	dodTagQueryFunction            uint32 = 0x420074
	dodTagRequestHeader            uint32 = 0x420077
	dodTagRequestMessage           uint32 = 0x420078
	dodTagRequestPayload           uint32 = 0x420079
	dodTagResponseMessage          uint32 = 0x42007b
	dodTagResultStatus             uint32 = 0x42007f
	dodTagSymmetricKey             uint32 = 0x42008f
	dodTagTemplateAttribute        uint32 = 0x420091
	dodTagUniqueIdentifier         uint32 = 0x420094
	dodTagWrappingMethod           uint32 = 0x42009e
	dodTagEncodingOption           uint32 = 0x4200a3

	dodOperationCreate           int32 = 0x01
	dodOperationRegister         int32 = 0x03
	dodOperationGet              int32 = 0x0a
	dodOperationRevoke           int32 = 0x13
	dodOperationDestroy          int32 = 0x14
	dodOperationQuery            int32 = 0x18
	dodOperationDiscoverVersions int32 = 0x1e
)

// TestDODKMIPProductionAssembly launches the exact full cmd/trstctl artifact
// through its Enterprise attach seam, drives raw KMIP over TLS 1.3 mTLS, then
// launches a second exact artifact over the same JetStream/KEK to prove replay.
func TestDODKMIPProductionAssembly(t *testing.T) {
	external := proof.StartCommand(t, "secrets_residuals.kmip_wrapping_profile_negotiation")
	verifierEndpoint := dodRightSizeLoopbackBridge(t, external.Endpoint())
	root := t.TempDir()
	licenseFile, trustedPublicKey := dodRightSizeLicense(t, root)
	first := proof.BuildShippedProcess(t, "secrets_residuals.kmip_wrapping_profile_negotiation", trustedPublicKey)
	second := proof.BuildShippedProcess(t, "secrets_residuals.kmip_wrapping_profile_negotiation", trustedPublicKey)
	postgresPort := dodFreePort(t)
	st, closeStore, err := server.DODOpenBundledStore(context.Background(), filepath.Join(root, "postgres"), postgresPort)
	if err != nil {
		t.Fatal(err)
	}
	_ = st
	t.Cleanup(closeStore)

	const serverName = "kmip.dod.test"
	mtlsDir := filepath.Join(root, "kmip-mtls")
	if err := os.Mkdir(mtlsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	material, err := mtls.GenerateSignerPeerMaterial(mtlsDir, serverName, time.Hour)
	if err != nil {
		t.Fatalf("generate KMIP mTLS material: %v", err)
	}
	httpPort := dodFreePort(t)
	kmipPort := dodFreePort(t)
	cfg := config.Default()
	cfg.Server.Addr = "127.0.0.1:" + strconv.Itoa(httpPort)
	cfg.Server.TLS.Mode = config.TLSDisabled
	cfg.Server.TLS.AllowPlaintextDev = true
	cfg.Postgres.Mode = config.PostgresExternal
	cfg.Postgres.DSN = fmt.Sprintf("postgres://postgres:postgres@127.0.0.1:%d/postgres", postgresPort)
	cfg.NATS.Mode = config.NATSEmbedded
	cfg.NATS.StoreDir = filepath.Join(root, "nats")
	cfg.License.File = licenseFile
	cfg.Migrate.Auto = true
	cfg.RateLimit.Enabled = false
	cfg.Telemetry.Enabled = false
	cfg.Audit.SigningKeyFile = filepath.Join(root, "audit-signing-key.pem")
	cfg.Secrets.EnableAPI = true
	cfg.Secrets.KEKFile = filepath.Join(root, "secrets-kek.bin")
	signerRuntimeDir, err := os.MkdirTemp("/tmp", "trstctl-kmip-dod-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(signerRuntimeDir) })
	cfg.Signer.Socket = filepath.Join(signerRuntimeDir, "signer.sock")
	cfg.Signer.KeyStoreDir = filepath.Join(root, "signer-keys")
	cfg.Signer.AuthSecretFile = filepath.Join(root, "signer-auth.bin")
	cfg.Signer.AllowInsecureDevNonLinux = true
	cfg.CA.CertFile = filepath.Join(root, "issuing-ca.pem")
	cfg.Protocols.KMIP = config.KMIPProtocol{
		Enabled: true, TenantID: dodRightSizeTenant, Addr: "127.0.0.1:" + strconv.Itoa(kmipPort),
		CertFile: material.Signer.CertFile, KeyFile: material.Signer.KeyFile,
		ClientCAFile: material.Signer.PeerCAFile,
	}
	configFile := dodRightSizeWriteConfig(t, root, cfg)
	env := dodRightSizeProcessEnv(configFile)
	_ = dodRightSizeBootstrapToken(t, first, root, env)
	baseURL := "http://127.0.0.1:" + strconv.Itoa(httpPort)
	httpClient := &http.Client{Timeout: 10 * time.Second}

	first.Start(root, env)
	dodRightSizeWaitHealthy(t, httpClient, baseURL, first)
	conn := dodKMIPDial(t, "127.0.0.1:"+strconv.Itoa(kmipPort), material, serverName)
	query := dodKMIPExchange(t, conn, dodOperationQuery, dodKMIPStructure(dodTagRequestPayload,
		dodKMIPEnum(dodTagQueryFunction, 1), dodKMIPEnum(dodTagQueryFunction, 10),
	))
	dodKMIPRequireSuccess(t, query, dodOperationQuery)
	discover := dodKMIPExchange(t, conn, dodOperationDiscoverVersions, dodKMIPStructure(dodTagRequestPayload,
		dodKMIPProtocolVersion(1, 4), dodKMIPProtocolVersion(1, 3),
	))
	dodKMIPRequireSuccess(t, discover, dodOperationDiscoverVersions)
	wrappingResponse := dodKMIPExchange(t, conn, dodOperationCreate, dodKMIPCreateAES256Payload())
	wrappingNode := dodKMIPRequireSuccess(t, wrappingResponse, dodOperationCreate)
	wrappingID := string(dodKMIPRequireNode(t, wrappingNode, dodTagUniqueIdentifier).value)
	keyMaterial := []byte("0123456789abcdef0123456789abcdef")
	defer secret.Wipe(keyMaterial)
	register := dodKMIPExchange(t, conn, dodOperationRegister, dodKMIPRegisterRawPayload(keyMaterial))
	registerNode := dodKMIPRequireSuccess(t, register, dodOperationRegister)
	registeredID := string(dodKMIPRequireNode(t, registerNode, dodTagUniqueIdentifier).value)
	wrappedGet := dodKMIPExchange(t, conn, dodOperationGet, dodKMIPGetWrappedPayload(registeredID, wrappingID))
	wrappedNode := dodKMIPRequireSuccess(t, wrappedGet, dodOperationGet)
	wrappedObject := dodKMIPRequireNode(t, wrappedNode, dodTagSymmetricKey)
	cloneRegister := dodKMIPExchange(t, conn, dodOperationRegister, dodKMIPStructure(dodTagRequestPayload,
		dodKMIPEnum(dodTagObjectType, 2), dodKMIPStructure(dodTagTemplateAttribute), dodKMIPEncodeNode(wrappedObject),
	))
	cloneNode := dodKMIPRequireSuccess(t, cloneRegister, dodOperationRegister)
	cloneID := string(dodKMIPRequireNode(t, cloneNode, dodTagUniqueIdentifier).value)
	cloneGet := dodKMIPExchange(t, conn, dodOperationGet, dodKMIPUniqueIDPayload(cloneID))
	cloneGetNode := dodKMIPRequireSuccess(t, cloneGet, dodOperationGet)
	if !bytes.Equal(dodKMIPRequireNode(t, cloneGetNode, dodTagKeyMaterial).value, keyMaterial) {
		t.Fatal("wrapped Register clone differs from supplied key")
	}
	dodKMIPRequireSuccess(t, dodKMIPExchange(t, conn, dodOperationRevoke, dodKMIPUniqueIDPayload(registeredID)), dodOperationRevoke)
	dodKMIPRequireSuccess(t, dodKMIPExchange(t, conn, dodOperationDestroy, dodKMIPUniqueIDPayload(cloneID)), dodOperationDestroy)
	_ = conn.Close()
	first.Stop()

	second.Start(root, env)
	dodRightSizeWaitHealthy(t, httpClient, baseURL, second)
	conn = dodKMIPDial(t, "127.0.0.1:"+strconv.Itoa(kmipPort), material, serverName)
	replayedRevoked := dodKMIPExchange(t, conn, dodOperationGet, dodKMIPUniqueIDPayload(registeredID))
	replayedDestroyed := dodKMIPExchange(t, conn, dodOperationGet, dodKMIPUniqueIDPayload(cloneID))
	if dodKMIPStatus(t, replayedRevoked, dodOperationGet) != 1 || dodKMIPStatus(t, replayedDestroyed, dodOperationGet) != 1 {
		t.Fatal("fresh shipped runtime did not replay revoke/destroy states")
	}
	_ = conn.Close()

	verification := map[string]any{
		"protocol": "oasis-kmip-1.4", "key_material_b64": base64.StdEncoding.EncodeToString(keyMaterial),
		"query": base64.StdEncoding.EncodeToString(query), "discover": base64.StdEncoding.EncodeToString(discover),
		"register": base64.StdEncoding.EncodeToString(register), "wrapped_get": base64.StdEncoding.EncodeToString(wrappedGet),
		"clone_get":              base64.StdEncoding.EncodeToString(cloneGet),
		"replayed_revoked_get":   base64.StdEncoding.EncodeToString(replayedRevoked),
		"replayed_destroyed_get": base64.StdEncoding.EncodeToString(replayedDestroyed),
	}
	verifierReadback := dodKMIPVerifyTranscript(t, verifierEndpoint, verification)
	editionsRequest, err := http.NewRequest(http.MethodGet, baseURL+"/v1/editions", nil)
	if err != nil {
		t.Fatal(err)
	}
	session := proof.StartResponse(t, "secrets_residuals.kmip_wrapping_profile_negotiation", second.Do(editionsRequest))
	executionReceipt := external.StopAndReceipt()
	transcript := bytes.Join([][]byte{query, discover, register, wrappedGet, cloneGet, replayedRevoked, replayedDestroyed}, nil)
	session.Complete(proof.IndependentInterop(proof.IndependentInteropProbe{
		ClientIdentity: []byte("OASIS KMIP 1.4 independent TTLV verifier"), Transcript: transcript,
		IndependentVerifier: verifierReadback, ExecutionReceipt: executionReceipt,
	}))
}

type dodKMIPNode struct {
	tag      uint32
	kind     byte
	value    []byte
	children []dodKMIPNode
}

func dodKMIPDial(t *testing.T, address string, material *mtls.SignerPeerMaterial, serverName string) net.Conn {
	t.Helper()
	var raw net.Conn
	var err error
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		raw, err = net.DialTimeout("tcp", address, time.Second)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial KMIP: %v", err)
	}
	conn, err := mtls.MutualTLSClientConnFromFiles(context.Background(), raw,
		material.ControlPlane.CertFile, material.ControlPlane.KeyFile,
		material.ControlPlane.PeerCAFile, serverName,
	)
	if err != nil {
		t.Fatalf("KMIP mTLS: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn
}

func dodKMIPExchange(t *testing.T, conn net.Conn, operation int32, payload []byte) []byte {
	t.Helper()
	frame := dodKMIPStructure(dodTagRequestMessage,
		dodKMIPStructure(dodTagRequestHeader, dodKMIPProtocolVersion(1, 4), dodKMIPInt(dodTagBatchCount, 1)),
		dodKMIPStructure(dodTagBatchItem, dodKMIPEnum(dodTagOperation, operation), payload),
	)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write KMIP operation %#x: %v", operation, err)
	}
	var header [8]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Fatalf("read KMIP operation %#x header: %v", operation, err)
	}
	length := int(binary.BigEndian.Uint32(header[4:]))
	total := 8 + length + (8-length%8)%8
	if total < 8 || total > 1<<20 {
		t.Fatalf("KMIP response size %d is invalid", total)
	}
	response := make([]byte, total)
	copy(response, header[:])
	if _, err := io.ReadFull(conn, response[8:]); err != nil {
		t.Fatalf("read KMIP operation %#x body: %v", operation, err)
	}
	return response
}

func dodKMIPRequireSuccess(t *testing.T, frame []byte, operation int32) dodKMIPNode {
	t.Helper()
	root := dodKMIPParse(t, frame)
	if root.tag != dodTagResponseMessage || dodKMIPStatusNode(t, root, operation) != 0 {
		t.Fatalf("KMIP operation %#x did not succeed", operation)
	}
	return root
}

func dodKMIPStatus(t *testing.T, frame []byte, operation int32) int32 {
	t.Helper()
	return dodKMIPStatusNode(t, dodKMIPParse(t, frame), operation)
}

func dodKMIPStatusNode(t *testing.T, root dodKMIPNode, operation int32) int32 {
	t.Helper()
	for _, item := range root.children {
		if item.tag != dodTagBatchItem {
			continue
		}
		if op, ok := dodKMIPDirectEnum(item, dodTagOperation); ok && op == operation {
			if status, exists := dodKMIPDirectEnum(item, dodTagResultStatus); exists {
				return status
			}
		}
	}
	t.Fatalf("KMIP response missing operation %#x", operation)
	return -1
}

func dodKMIPDirectEnum(node dodKMIPNode, tag uint32) (int32, bool) {
	for _, child := range node.children {
		if child.tag == tag && child.kind == dodTTLVEnumeration && len(child.value) == 4 {
			return int32(binary.BigEndian.Uint32(child.value)), true
		}
	}
	return 0, false
}

func dodKMIPRequireNode(t *testing.T, root dodKMIPNode, tag uint32) dodKMIPNode {
	t.Helper()
	if node, ok := dodKMIPFind(root, tag); ok {
		return node
	}
	t.Fatalf("KMIP response missing tag %#06x", tag)
	return dodKMIPNode{}
}

func dodKMIPFind(root dodKMIPNode, tag uint32) (dodKMIPNode, bool) {
	if root.tag == tag {
		return root, true
	}
	for _, child := range root.children {
		if found, ok := dodKMIPFind(child, tag); ok {
			return found, true
		}
	}
	return dodKMIPNode{}, false
}

func dodKMIPParse(t *testing.T, raw []byte) dodKMIPNode {
	t.Helper()
	fields := 0
	node, used, err := dodKMIPParseItem(raw, 1, &fields)
	if err != nil || used != len(raw) {
		t.Fatalf("parse KMIP response: used=%d bytes=%d fields=%d err=%v", used, len(raw), fields, err)
	}
	return node
}

func dodKMIPParseItem(raw []byte, depth int, fields *int) (dodKMIPNode, int, error) {
	if depth > 16 || len(raw) < 8 {
		return dodKMIPNode{}, 0, fmt.Errorf("depth/header bound")
	}
	*fields++
	if *fields > 4096 {
		return dodKMIPNode{}, 0, fmt.Errorf("field bound")
	}
	tag := uint32(raw[0])<<16 | uint32(raw[1])<<8 | uint32(raw[2])
	kind := raw[3]
	length := int(binary.BigEndian.Uint32(raw[4:8]))
	total := 8 + length + (8-length%8)%8
	if length < 0 || total > len(raw) || total > 1<<20 {
		return dodKMIPNode{}, 0, fmt.Errorf("length bound")
	}
	node := dodKMIPNode{tag: tag, kind: kind}
	value := raw[8 : 8+length]
	if kind == dodTTLVStructure {
		for offset := 0; offset < len(value); {
			child, used, err := dodKMIPParseItem(value[offset:], depth+1, fields)
			if err != nil {
				return dodKMIPNode{}, 0, err
			}
			node.children = append(node.children, child)
			offset += used
		}
	} else {
		node.value = append([]byte(nil), value...)
	}
	return node, total, nil
}

func dodKMIPEncodeNode(node dodKMIPNode) []byte {
	if node.kind != dodTTLVStructure {
		return dodKMIPItem(node.tag, node.kind, node.value)
	}
	children := make([][]byte, 0, len(node.children))
	for _, child := range node.children {
		children = append(children, dodKMIPEncodeNode(child))
	}
	return dodKMIPStructure(node.tag, children...)
}

func dodKMIPCreateAES256Payload() []byte {
	return dodKMIPStructure(dodTagRequestPayload,
		dodKMIPEnum(dodTagObjectType, 2),
		dodKMIPStructure(dodTagTemplateAttribute),
	)
}

func dodKMIPRegisterRawPayload(key []byte) []byte {
	return dodKMIPStructure(dodTagRequestPayload,
		dodKMIPEnum(dodTagObjectType, 2), dodKMIPStructure(dodTagTemplateAttribute),
		dodKMIPStructure(dodTagSymmetricKey, dodKMIPStructure(dodTagKeyBlock,
			dodKMIPEnum(dodTagKeyFormatType, 1),
			dodKMIPStructure(dodTagKeyValue, dodKMIPItem(dodTagKeyMaterial, dodTTLVBytes, key)),
			dodKMIPEnum(dodTagCryptographicAlgorithm, 3), dodKMIPInt(dodTagCryptographicLength, 256),
		)),
	)
}

func dodKMIPGetWrappedPayload(id, wrappingID string) []byte {
	return dodKMIPStructure(dodTagRequestPayload, dodKMIPText(dodTagUniqueIdentifier, id),
		dodKMIPStructure(dodTagKeyWrappingSpecification,
			dodKMIPEnum(dodTagWrappingMethod, 1),
			dodKMIPStructure(dodTagEncryptionKeyInformation,
				dodKMIPText(dodTagUniqueIdentifier, wrappingID),
				dodKMIPStructure(dodTagCryptographicParameters, dodKMIPEnum(dodTagBlockCipherMode, 9)),
			),
			dodKMIPEnum(dodTagEncodingOption, 1),
		),
	)
}

func dodKMIPUniqueIDPayload(id string) []byte {
	return dodKMIPStructure(dodTagRequestPayload, dodKMIPText(dodTagUniqueIdentifier, id))
}

func dodKMIPProtocolVersion(major, minor int32) []byte {
	return dodKMIPStructure(dodTagProtocolVersion, dodKMIPInt(dodTagProtocolVersionMajor, major), dodKMIPInt(dodTagProtocolVersionMinor, minor))
}

func dodKMIPStructure(tag uint32, children ...[]byte) []byte {
	return dodKMIPItem(tag, dodTTLVStructure, bytes.Join(children, nil))
}

func dodKMIPInt(tag uint32, value int32) []byte {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], uint32(value))
	return dodKMIPItem(tag, dodTTLVInteger, raw[:])
}

func dodKMIPEnum(tag uint32, value int32) []byte {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], uint32(value))
	return dodKMIPItem(tag, dodTTLVEnumeration, raw[:])
}

func dodKMIPText(tag uint32, value string) []byte {
	return dodKMIPItem(tag, dodTTLVText, []byte(value))
}

func dodKMIPItem(tag uint32, kind byte, value []byte) []byte {
	out := make([]byte, 8+len(value)+(8-len(value)%8)%8)
	out[0], out[1], out[2], out[3] = byte(tag>>16), byte(tag>>8), byte(tag), kind
	binary.BigEndian.PutUint32(out[4:8], uint32(len(value)))
	copy(out[8:], value)
	return out
}

func dodKMIPVerifyTranscript(t *testing.T, endpoint string, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.Post(endpoint+"/v1/verify", "application/json", bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("KMIP independent verifier: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil || response.StatusCode != http.StatusOK || len(body) < 16 {
		t.Fatalf("KMIP independent verifier status=%d bytes=%d err=%v body=%s", response.StatusCode, len(body), err, body)
	}
	return body
}
