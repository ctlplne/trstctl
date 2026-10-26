// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"fmt"
	"log"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/connector"
	connectorwasm "trstctl.com/trstctl/internal/connector/wasm/host"
)

// applyConnectorIsolation sets how this agent runs the shipped connector
// families and, for the sandbox, starts compiling the embedded module so the
// first job does not wait for it.
func applyConnectorIsolation(mode string) error {
	switch mode {
	case connector.IsolationWASM:
		relay.SetConnectorsInProcess(false)
		go func() {
			if _, err := connectorwasm.Builtin(); err != nil {
				log.Printf("trstctl-agent: the connector sandbox is unavailable; connector jobs will fail until it loads or the agent runs with --connector-isolation=%s: %v", connector.IsolationInProcessFlag, err)
			}
		}()
	case connector.IsolationInProcessFlag:
		relay.SetConnectorsInProcess(true)
	default:
		return fmt.Errorf("--connector-isolation must be %q or %q, not %q", connector.IsolationWASM, connector.IsolationInProcessFlag, mode)
	}
	return nil
}
