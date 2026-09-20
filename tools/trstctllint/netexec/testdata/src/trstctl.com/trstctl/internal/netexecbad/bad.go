// SPDX-License-Identifier: BUSL-1.1

package netexecbad

import (
	nethttp "net/http"
	run "os/exec"
	"time"
)

var client = nethttp.DefaultClient // want `http.DefaultClient is not allowed in new outbound surfaces`

func shellReload() error {
	return run.Command("sh", "-c", "reload").Run() // want `direct shell interpreter execution is not allowed`
}

func spawn(path string) error {
	return run.Command(path).Run() // want `exec.Command is not allowed in new process surfaces`
}

// fetch builds its own client instead of asking netsec/egress for one. The
// import alias proves the rule resolves types rather than matching the source
// spelling "http.Client".
func fetch(url string) error {
	c := &nethttp.Client{Timeout: time.Second} // want `ambient http.Client construction is not allowed in new outbound surfaces`
	// Calling Get on an already-constructed client is the shape we WANT, so this
	// line must stay diagnostic-free; analysistest fails on any extra report.
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	if err := resp.Body.Close(); err != nil {
		return err
	}
	return nil
}

// fetchAmbient uses the package-level helper, which silently routes through
// http.DefaultClient and so bypasses both the SSRF transport and the egress guard.
func fetchAmbient(url string) error {
	resp, err := nethttp.Get(url) // want `http.Get/http.Head/http.Post/http.PostForm are not allowed`
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// postAmbient covers the write-side helper by value literal as well as pointer.
func postAmbient(url string) error {
	c := nethttp.Client{} // want `ambient http.Client construction is not allowed in new outbound surfaces`
	_ = c
	resp, err := nethttp.Post(url, "application/json", nil) // want `http.Get/http.Head/http.Post/http.PostForm are not allowed`
	if err != nil {
		return err
	}
	return resp.Body.Close()
}
