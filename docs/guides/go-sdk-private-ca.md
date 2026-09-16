# Connect the Go SDK to a private CA

Use this example when the control plane has an evaluation certificate or a
certificate issued by your private CA. Go's default HTTP client trusts the
operating system's roots; `TRSTCTL_CA_FILE` is not read by `trstctl.New`.

The SDK is distributed in the repository. From a new application directory,
initialize a Go module and point it at your checkout:

```sh
export TRSTCTL_SOURCE=/path/to/your/trstctl
go mod init example.com/trstctl-client-example
go mod edit -replace "trstctl.com/sdk/go=$TRSTCTL_SOURCE/clients/sdk/go"
```

Save the program below as `main.go` in that directory, then run:

```sh
export TRSTCTL_SERVER=https://localhost:8443
export TRSTCTL_CA_FILE="$PWD/trstctl-eval-ca.pem"
# Supply TRSTCTL_TOKEN through your normal private credential mechanism.
go mod tidy
go run .
```

The CA file must be the public bundle you captured and inspected during
[Getting started](../getting-started.md). This client adds that bundle to the
system roots, retains hostname and expiry checks, and uses a 30-second timeout.
A missing or malformed configured bundle stops the program; it never falls back
to unverified TLS. If the server uses a CA already trusted by the operating
system, leave `TRSTCTL_CA_FILE` unset.

```go
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	trstctl "trstctl.com/sdk/go/trstctl"
)

func run() error {
	// Go's default transport trusts the operating system's certificate roots.
	// Add the operator-selected CA bundle for a self-hosted private-CA endpoint.
	roots, err := x509.SystemCertPool()
	if err != nil {
		return fmt.Errorf("load system certificate roots: %w", err)
	}
	caFile := os.Getenv("TRSTCTL_CA_FILE")
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return fmt.Errorf("read control-plane CA bundle: %w", err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return fmt.Errorf("control-plane CA bundle contains no certificates")
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	serverURL, token := os.Getenv("TRSTCTL_SERVER"), os.Getenv("TRSTCTL_TOKEN")
	if serverURL == "" || token == "" {
		return fmt.Errorf("set TRSTCTL_SERVER and TRSTCTL_TOKEN")
	}
	client := trstctl.New(serverURL, token,
		trstctl.WithHTTPClient(&http.Client{Transport: transport, Timeout: 30 * time.Second}))
	it := client.Certificates(trstctl.CertificateListOptions{ListOptions: trstctl.ListOptions{Limit: 50}})
	for it.Next(context.Background()) {
		if _, err := fmt.Fprintln(os.Stdout, it.Value().ID); err != nil {
			return err
		}
	}
	return it.Err()
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
```

The iterator requests 50 certificates at a time and follows `next_cursor` until
there are no more pages. The token needs `certs:read`. The server still checks the
token's tenant and permissions on every request. `WithHTTPClient` changes transport
configuration; it does not change SDK retry or idempotency behavior.
