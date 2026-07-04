// SPDX-License-Identifier: MPL-2.0

package netexecbad

import (
	nethttp "net/http"
	run "os/exec"
)

var client = nethttp.DefaultClient // want `http.DefaultClient is not allowed in new outbound surfaces`

func shellReload() error {
	return run.Command("sh", "-c", "reload").Run() // want `direct shell interpreter execution is not allowed`
}

func spawn(path string) error {
	return run.Command(path).Run() // want `exec.Command is not allowed in new process surfaces`
}
