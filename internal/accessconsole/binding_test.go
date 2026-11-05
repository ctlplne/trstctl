// SPDX-License-Identifier: BUSL-1.1
package accessconsole

import (
	"testing"
)

func TestConsoleBindingOnlyUsesReviewedNativeEndpointsOrExplicitLoopback(t *testing.T) {
	base := Binding{FederationEndpoint: "https://signin.aws.amazon.com/federation", Destination: "https://console.aws.amazon.com/"}
	if err := base.Validate(false); err != nil {
		t.Fatal(err)
	}
	for _, b := range []Binding{{FederationEndpoint: "https://us-east-1.signin.aws.amazon.com/federation", Destination: "https://us-east-1.console.aws.amazon.com/s3/home"}, {FederationEndpoint: "http://127.0.0.1:1234/federation", Destination: "http://127.0.0.1:1234/console"}} {
		if b.Validate(true) != nil {
			t.Fatal("supported native/owned-lab binding refused")
		}
	}
	for _, change := range []func(*Binding){func(b *Binding) { b.FederationEndpoint = "https://signin.aws.amazon.com.evil.example/federation" }, func(b *Binding) { b.FederationEndpoint = "https://user:password@signin.aws.amazon.com/federation" }, func(b *Binding) { b.FederationEndpoint = "https://signin.aws.amazon.com/federation?Session=foreign" }, func(b *Binding) { b.FederationEndpoint = "https://signin.aws.amazon.com/federation#foreign" }, func(b *Binding) { b.FederationEndpoint = "https://signin.aws.amazon.com:8443/federation" }, func(b *Binding) { b.FederationEndpoint = "https://signin.aws.amazon.com/other" }, func(b *Binding) { b.FederationEndpoint = "http://signin.aws.amazon.com/federation" }, func(b *Binding) { b.Destination = "https://console.aws.amazon.com.evil.example/" }, func(b *Binding) { b.Destination = "javascript:alert(1)" }, func(b *Binding) { b.Destination = "https://console.aws.amazon.com/?access_token=foreign" }, func(b *Binding) { b.Destination = "http://127.0.0.1:1234/console" }} {
		b := base
		change(&b)
		if b.Validate(false) == nil {
			t.Fatal("unreviewable console authority accepted")
		}
	}
}
func FuzzConsoleBinding(f *testing.F) {
	f.Add("https://signin.aws.amazon.com/federation", "https://console.aws.amazon.com/")
	f.Add("http://127.0.0.1/federation", "http://127.0.0.1/console")
	f.Fuzz(func(t *testing.T, endpoint, destination string) {
		b := Binding{endpoint, destination}
		if b.Validate(false) == nil && b.Validate(true) != nil {
			t.Fatal("loopback opt-in removed a valid native binding")
		}
	})
}
