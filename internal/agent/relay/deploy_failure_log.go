// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"bytes"
	"log"
)

// deployFailureLogLimit bounds the reason the relay writes for one failed
// deploy.
const deployFailureLogLimit = 2048

// logDeployFailure writes why a deploy failed to this host's own log (B2). The
// report to the control plane carries only a closed phrase, because the
// connector's error can contain whatever the appliance echoed back, the
// credential included; the reason stays here, with every redeemed value
// redacted, for an operator with access to this host.
func logDeployFailure(job Job, intent DeployIntent, err error, material Material) {
	log.Printf("trstctl-agent: job %d: %s deploy to %s failed: %s", job.JobID, intent.Connector, intent.Target,
		redactRedeemed(err.Error(), material))
}

// redactRedeemed removes every redeemed value from text, and every line of a
// multi-line value (a PEM key echoed one line at a time), working on the
// material's own bytes so no further copy of a secret is made.
func redactRedeemed(text string, material Material) string {
	out := []byte(text)
	mask := []byte("[redacted]")
	for _, value := range material {
		if v := bytes.TrimSpace(value); len(v) >= 4 {
			out = bytes.ReplaceAll(out, v, mask)
		}
	}
	for _, value := range material {
		for _, line := range bytes.Split(value, []byte("\n")) {
			if line = bytes.TrimSpace(line); len(line) >= 16 {
				out = bytes.ReplaceAll(out, line, mask)
			}
		}
	}
	if len(out) > deployFailureLogLimit {
		out = append(out[:deployFailureLogLimit], "…"...)
	}
	return string(out)
}
