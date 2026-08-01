// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestKMIPIndependentVerifierScopesBatchMetadataToDirectChildren(t *testing.T) {
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
import importlib.util, sys
spec = importlib.util.spec_from_file_location("kmip14_client", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
enum = lambda tag, value: module.Node(tag, module.ENUMERATION, value.to_bytes(4, "big"), [])
payload = module.Node(0x42007C, module.STRUCTURE, b"", [enum(module.TAG_OPERATION, module.OP_REGISTER)])
batch = module.Node(module.TAG_BATCH_ITEM, module.STRUCTURE, b"", [
    enum(module.TAG_OPERATION, module.OP_QUERY),
    enum(module.TAG_RESULT_STATUS, module.STATUS_SUCCESS),
    payload,
])
root = module.Node(module.TAG_RESPONSE_MESSAGE, module.STRUCTURE, b"", [batch])
assert module.batch_status(root, module.OP_QUERY) == module.STATUS_SUCCESS
assert module.batch_payload(root, module.OP_QUERY) is payload
`
	if output, err := exec.Command(python, "-c", program, module).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Fatalf("KMIP independent verifier direct-child regression: %v: %s", err, output)
	}
}
