// SPDX-License-Identifier: MPL-2.0

package main

import "strings"

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
	if o.allowInsecureLoopbackEnrollment {
		args = append(args, "--allow-insecure-loopback-enrollment")
	}
	if o.serverName != "" {
		args = append(args, "--server-name", o.serverName)
	}
	// A3: a relay installed as a Windows service must still be a relay when the
	// SCM restarts it. A flag omitted here is silently dropped on every
	// service-managed start — the agent comes back up looking healthy and
	// claiming nothing, which reads as a stalled queue rather than as lost
	// configuration.
	// C1: PKCS#11 token inventory must survive an SCM restart too, PIN file
	// path included — dropping it would silently downgrade a configured token
	// inventory to public objects only.
	if o.inventoryPKCS11Module != "" {
		args = append(args, "--inventory-pkcs11-module", o.inventoryPKCS11Module)
		if o.inventoryPKCS11Token != "" {
			args = append(args, "--inventory-pkcs11-token", o.inventoryPKCS11Token)
		}
		if o.inventoryPKCS11PINFile != "" {
			args = append(args, "--inventory-pkcs11-pin-file", o.inventoryPKCS11PINFile)
		}
	}
	// C1: a Windows agent installed as a service is the main consumer of the
	// Windows store inventory, so dropping these on an SCM restart would silence
	// exactly the estate they exist to see.
	if len(o.inventoryWindowsStores) > 0 {
		args = append(args, "--inventory-windows-stores", strings.Join(o.inventoryWindowsStores, ","))
		if o.inventoryWindowsLocation != "" {
			args = append(args, "--inventory-windows-location", o.inventoryWindowsLocation)
		}
	}
	if o.hostExecProfile != "" {
		// D1: without the profile an SCM-restarted agent claims no file/reload
		// deploys and looks perfectly healthy doing it.
		args = append(args, "--host-exec-profile", o.hostExecProfile)
		if o.hostRollbackDir != "" {
			// G1: the predecessor ledger must survive an SCM restart at the exact
			// operator-owned location; otherwise rollback disappears precisely
			// when restart durability is supposed to prove it.
			args = append(args, "--host-rollback-dir", o.hostRollbackDir)
		}
	}
	if o.relayClaim {
		args = append(args, "--relay-claim")
		if o.relayPollEvery > 0 {
			args = append(args, "--relay-poll-every", o.relayPollEvery.String())
		}
	}
	// A4: a Windows network relay must keep serving the same dark segment and
	// stable public authority after SCM restart. Dropping any one of these flags
	// either turns the proxy off or makes stock ACME URLs leave the relay path.
	if o.enrollProxyListen != "" {
		args = append(args,
			"--enroll-proxy-listen", o.enrollProxyListen,
			"--enroll-proxy-upstream", o.enrollProxyUpstream,
			"--enroll-proxy-segment", o.enrollProxySegment,
			"--enroll-proxy-public-url", o.enrollProxyPublicURL,
		)
	}
	return args
}
