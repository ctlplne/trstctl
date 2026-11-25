// SPDX-License-Identifier: BUSL-1.1
package cli

import (
	"net"
	"os"
	"path/filepath"
	"strings"

	"testing"
)

func TestAWSClientLineRequiresReviewedSigningScope(t *testing.T) {
	local := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8000}
	capability := strings.Repeat("a", 64)
	dir := t.TempDir()
	line, err := gatewayClientLine("aws", local, "", "", "", gatewayDelivery{AWSService: "s3", AWSRegion: "us-east-1", localCapability: capability, localArtifactDir: dir})
	if err != nil || !strings.Contains(line, "--profile trstctl-tunnel --endpoint-url http://127.0.0.1:8000 --region us-east-1 s3api <operation>") || !strings.Contains(line, "AWS_CONFIG_FILE=/dev/null") || strings.Contains(line, "--no-sign-request") {
		t.Fatalf("CLI omitted scoped, capability-bearing AWS request: %q, %v", line, err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatalf("private AWS client file = %v, %v", files, err)
	}
	info, err := files[0].Info()
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("AWS client file permission = %v, %v", info, err)
	}
	content, err := os.ReadFile(filepath.Join(dir, files[0].Name())) // #nosec G304 -- file was created by gatewayClientLine in this test's private temporary directory (CWE-22)
	if err != nil || !strings.Contains(string(content), "aws_session_token = "+capability) || !strings.Contains(line, files[0].Name()) {
		t.Fatalf("AWS client file does not bind the local capability: %v", err)
	}
	for _, scope := range []gatewayDelivery{{}, {AWSService: "iam", AWSRegion: "us-east-1"}, {AWSService: "s3", AWSRegion: "us-east-1;id"}, {AWSService: "s3", AWSRegion: "$(id)"}} {
		scope.localCapability, scope.localArtifactDir = capability, dir
		if _, err := gatewayClientLine("aws", local, "", "", "", scope); err == nil {
			t.Fatal("missing or unsafe signing scope reached command text")
		}
	}
}

func TestGCPClientLineCarriesNoNativeCredential(t *testing.T) {
	capability := strings.Repeat("b", 64)
	dir := t.TempDir()
	line, err := gatewayClientLine("gcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8000}, "", "", "", gatewayDelivery{localCapability: capability, localArtifactDir: dir})
	if err != nil || !strings.Contains(line, "curl --fail-with-body --header @") || !strings.Contains(line, "http://127.0.0.1:8000/<API-path>") {
		t.Fatalf("GCP client command omitted the local capability file: %q, %v", line, err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatalf("private HTTP client file = %v, %v", files, err)
	}
	content, err := os.ReadFile(filepath.Join(dir, files[0].Name())) // #nosec G304 -- file was created by gatewayClientLine in this test's private temporary directory (CWE-22)
	if err != nil || string(content) != "X-Trstctl-Tunnel-Token: "+capability+"\n" {
		t.Fatalf("GCP client file lacks its local header: %v", err)
	}
}
