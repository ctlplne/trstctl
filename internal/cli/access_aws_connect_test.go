// SPDX-License-Identifier: BUSL-1.1
package cli

import (
	"net"

	"testing"
)

func TestAWSClientLineRequiresReviewedSigningScope(t *testing.T) {
	local := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8000}
	line, err := gatewayClientLine("aws", local, "", "", "", gatewayDelivery{AWSService: "s3", AWSRegion: "us-east-1"})
	if err != nil || line != "aws --no-sign-request --endpoint-url http://127.0.0.1:8000 --region us-east-1 s3api <operation>" {
		t.Fatal("CLI omitted reviewed signing scope")
	}
	for _, scope := range []gatewayDelivery{{}, {AWSService: "iam", AWSRegion: "us-east-1"}, {AWSService: "s3", AWSRegion: "us-east-1;id"}, {AWSService: "s3", AWSRegion: "$(id)"}} {
		if _, err := gatewayClientLine("aws", local, "", "", "", scope); err == nil {
			t.Fatal("missing or unsafe signing scope reached command text")
		}
	}
}
