// SPDX-License-Identifier: MPL-2.0

package main

// serviceArguments are the flags the Windows service is launched with so that,
// when the SCM starts it, it reproduces this configuration and runs the loop.
func serviceArguments(o agentOptions) []string {
	args := []string{
		"--service=run",
		"--enroll-url", o.enrollURL,
		"--ca-bundle", o.caBundle,
		"--server", o.serverAddr,
		"--name", o.commonName,
		"--key", o.keyPath,
		"--cert", o.certPath,
		"--rotate-every", o.rotateEvery.String(),
	}
	if o.tokenFile != "" {
		args = append(args, "--bootstrap-token-file", o.tokenFile)
	}
	if o.serverName != "" {
		args = append(args, "--server-name", o.serverName)
	}
	// A3: a relay installed as a Windows service must still be a relay when the
	// SCM restarts it. A flag omitted here is silently dropped on every
	// service-managed start — the agent comes back up looking healthy and
	// claiming nothing, which reads as a stalled queue rather than as lost
	// configuration.
	if o.relayClaim {
		args = append(args, "--relay-claim")
		if o.relayPollEvery > 0 {
			args = append(args, "--relay-poll-every", o.relayPollEvery.String())
		}
	}
	return args
}
