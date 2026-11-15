// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

// TestMachineAuthExchangeUsesIsBoundedM4L4: exchange_uses is 1 to 10 (0
// means 1) on a method whose subject token is a JWT, and refused on aws-iam,
// whose login takes no JWT to exchange.
func TestMachineAuthExchangeUsesIsBoundedM4L4(t *testing.T) {
	kubernetes := func(uses int) MachineAuthMethod {
		return MachineAuthMethod{Name: "kubernetes", TenantID: "11111111-1111-1111-1111-111111111111", Issuer: "https://kubernetes.default.svc",
			Audience: "trstctl", JWKSJSON: `{"keys":[]}`, AllowedNamespaces: []string{"apps"}, Scopes: []string{"secrets:read"}, ExchangeUses: uses}
	}
	mentions := func(errs []error) bool {
		for _, err := range errs {
			if strings.Contains(err.Error(), "exchange_uses") {
				return true
			}
		}
		return false
	}
	for _, uses := range []int{0, 1, 3, MaxMachineAuthExchangeUses} {
		if errs := validateSecretsMachineAuth([]MachineAuthMethod{kubernetes(uses)}); mentions(errs) {
			t.Fatalf("exchange_uses %d was refused: %v", uses, errs)
		}
	}
	for _, uses := range []int{-1, MaxMachineAuthExchangeUses + 1} {
		if errs := validateSecretsMachineAuth([]MachineAuthMethod{kubernetes(uses)}); !mentions(errs) {
			t.Fatalf("exchange_uses %d was accepted", uses)
		}
	}
	aws := MachineAuthMethod{Name: "aws-iam", TenantID: "11111111-1111-1111-1111-111111111111", AllowedAccounts: []string{"111122223333"},
		Scopes: []string{"secrets:read"}, ExchangeUses: 2}
	if errs := validateSecretsMachineAuth([]MachineAuthMethod{aws}); !mentions(errs) {
		t.Fatal("exchange_uses on aws-iam was accepted")
	}
}
