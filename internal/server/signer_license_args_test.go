// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"reflect"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

func TestAUD56SupervisedSignerReceivesControlPlaneDeploymentBinding(t *testing.T) {
	got := appendSignerLicenseArgs(nil, config.License{
		File: "/etc/trstctl/license.json", DeploymentID: "acme-stage", Environment: "non_production",
	})
	want := []string{
		"--license", "/etc/trstctl/license.json",
		"--license-deployment-id", "acme-stage",
		"--license-environment", "non_production",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("signer license args = %#v, want %#v", got, want)
	}
}
