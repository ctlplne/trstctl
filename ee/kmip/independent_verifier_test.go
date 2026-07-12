// SPDX-License-Identifier: LicenseRef-trstctl-EE

package kmip

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestKMIPIndependentVerifierAcceptsRealServerTranscript(t *testing.T) {
	ctx := context.Background()
	server := New("tenant-a", certAuth{}, &auditsink.Recorder{})
	t.Cleanup(server.Close)
	client := []byte("good-client")

	query, err := server.HandleFrame(ctx, client, kmipRequestFrame(OperationQuery,
		ttlvStructure(TagRequestPayload,
			ttlvEnumeration(TagQueryFunction, queryFunctionOperations),
			ttlvEnumeration(TagQueryFunction, queryFunctionProfiles),
		),
	))
	if err != nil {
		t.Fatal(err)
	}
	discover, err := server.HandleFrame(ctx, client, kmipRequestFrame(OperationDiscoverVersions,
		ttlvStructure(TagRequestPayload, protocolVersionTTLV(1, 4), protocolVersionTTLV(1, 3)),
	))
	if err != nil {
		t.Fatal(err)
	}

	wrappingResponse, err := server.HandleFrame(ctx, client, kmipRequestFrame(OperationCreate, kmipCreateAES256Payload()))
	if err != nil {
		t.Fatal(err)
	}
	wrappingID := mustFindText(t, mustKMIPSuccess(t, wrappingResponse, OperationCreate), TagUniqueIdentifier)
	keyMaterial := []byte("0123456789abcdef0123456789abcdef")
	defer secret.Wipe(keyMaterial)
	register, err := server.HandleFrame(ctx, client, kmipRequestFrame(OperationRegister, kmipRegisterRawAES256Payload(keyMaterial)))
	if err != nil {
		t.Fatal(err)
	}
	registeredID := mustFindText(t, mustKMIPSuccess(t, register, OperationRegister), TagUniqueIdentifier)
	wappedGet, err := server.HandleFrame(ctx, client, kmipRequestFrame(OperationGet, kmipGetWrappedPayload(registeredID, wrappingID, encodingOptionNoEncoding)))
	if err != nil {
		t.Fatal(err)
	}
	wrappedObject := mustFindNode(t, mustKMIPSuccess(t, wappedGet, OperationGet), TagSymmetricKey)
	cloneRegister, err := server.HandleFrame(ctx, client, kmipRequestFrame(OperationRegister,
		ttlvStructure(TagRequestPayload,
			ttlvEnumeration(TagObjectType, objectTypeSymmetricKey),
			ttlvStructure(TagTemplateAttribute),
			encodeParsedTTLV(wrappedObject),
		),
	))
	if err != nil {
		t.Fatal(err)
	}
	cloneID := mustFindText(t, mustKMIPSuccess(t, cloneRegister, OperationRegister), TagUniqueIdentifier)
	cloneGet, err := server.HandleFrame(ctx, client, kmipRequestFrame(OperationGet, kmipUniqueIDPayload(cloneID)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.HandleFrame(ctx, client, kmipRequestFrame(OperationRevoke, kmipUniqueIDPayload(registeredID))); err != nil {
		t.Fatal(err)
	}
	if _, err := server.HandleFrame(ctx, client, kmipRequestFrame(OperationDestroy, kmipUniqueIDPayload(cloneID))); err != nil {
		t.Fatal(err)
	}
	revokedGet, err := server.HandleFrame(ctx, client, kmipRequestFrame(OperationGet, kmipUniqueIDPayload(registeredID)))
	if err != nil {
		t.Fatal(err)
	}
	destroyedGet, err := server.HandleFrame(ctx, client, kmipRequestFrame(OperationGet, kmipUniqueIDPayload(cloneID)))
	if err != nil {
		t.Fatal(err)
	}

	payload := map[string]any{
		"protocol":               "oasis-kmip-1.4",
		"key_material_b64":       base64.StdEncoding.EncodeToString(keyMaterial),
		"query":                  base64.StdEncoding.EncodeToString(query),
		"discover":               base64.StdEncoding.EncodeToString(discover),
		"register":               base64.StdEncoding.EncodeToString(register),
		"wrapped_get":            base64.StdEncoding.EncodeToString(wappedGet),
		"clone_get":              base64.StdEncoding.EncodeToString(cloneGet),
		"replayed_revoked_get":   base64.StdEncoding.EncodeToString(revokedGet),
		"replayed_destroyed_get": base64.StdEncoding.EncodeToString(destroyedGet),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 is required by the committed KMIP substrate")
	}
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	module := filepath.Join(repo, "tools", "dodcensus", "substrates", "kmip14_client.py")
	program := `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("kmip14_client", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
sys.stdout.buffer.write(module.verify_kmip(json.load(sys.stdin)))
`
	command := exec.Command(python, "-c", program, module)
	command.Stdin = bytes.NewReader(encoded)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("independent KMIP transcript verifier: %v: %s", err, output)
	}
}
