// SPDX-License-Identifier: BUSL-1.1

package netsec

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A200-L1: the metadata client takes only AWS's link-local credential
// addresses and loopback, over plain HTTP, by address.
func TestCloudMetadataClientAcceptsOnlyMetadataAndLoopbackAddressesA200L1(t *testing.T) {
	for _, endpoint := range []string{
		"http://169.254.169.254",
		"http://169.254.169.254/latest/api/token",
		"http://[fd00:ec2::254]",
		"http://169.254.170.2/v2/credentials/task",
		"http://169.254.170.23/v1/credentials",
		"http://[fd00:ec2::23]/v1/credentials",
		"http://127.0.0.1:8080/credentials",
		"http://[::1]:9911/credentials",
	} {
		if _, err := CloudMetadataClient(endpoint, time.Second); err != nil {
			t.Errorf("CloudMetadataClient(%q) = %v, want accepted", endpoint, err)
		}
	}
	for _, endpoint := range []string{
		"https://169.254.169.254",
		"http://localhost:8080",
		"http://metadata.internal",
		"http://10.0.0.1",
		"http://169.254.169.253",
		"http://192.0.2.10",
		"http://operator@169.254.169.254",
		"http://[fe80::1%25en0]",
		"http://169.254.169.254:0",
		"169.254.169.254",
		"ftp://169.254.169.254",
	} {
		if _, err := CloudMetadataClient(endpoint, time.Second); !errors.Is(err, ErrSSRFBlocked) {
			t.Errorf("CloudMetadataClient(%q) = %v, want ErrSSRFBlocked", endpoint, err)
		}
	}
}

// A200-L1: the client reads the endpoint it was built for, consults no
// proxy, refuses a redirect, and will not dial any other address.
func TestCloudMetadataClientDialsOnlyItsAddressA200L1(t *testing.T) {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/credentials", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "credentials")
	}))
	defer stub.Close()
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the metadata client reached an address it was not built for")
	}))
	defer other.Close()

	client, err := CloudMetadataClient(stub.URL, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatalf("metadata transport = %T with a proxy function, want no proxy", client.Transport)
	}
	resp, err := client.Get(stub.URL + "/credentials")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "credentials" {
		t.Fatalf("metadata read = %d %q", resp.StatusCode, body)
	}
	if _, err := client.Get(stub.URL + "/redirect"); err == nil || !strings.Contains(err.Error(), "refuses redirects") {
		t.Fatalf("redirect = %v, want refused", err)
	}
	if _, err := client.Get(other.URL + "/credentials"); !errors.Is(err, ErrSSRFBlocked) {
		t.Fatalf("another address = %v, want ErrSSRFBlocked", err)
	}
}
