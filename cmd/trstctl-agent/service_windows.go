// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package main

import (
	"context"
	"fmt"
	"os"

	"trstctl.com/trstctl/internal/agent/winservice"
)

// handleService implements the --service control verbs on Windows: install and
// uninstall register/remove the agent with the Service Control Manager, and run
// executes the agent loop under the SCM.
func handleService(action string, o agentOptions) error {
	switch action {
	case "run":
		return winservice.Run(winservice.DefaultServiceName, func(ctx context.Context) error {
			return runAgent(ctx, o)
		})
	case "install":
		if o.inlineToken != "" {
			return fmt.Errorf("inline bootstrap tokens are not persisted for Windows services; use --bootstrap-token-file")
		}
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("locate executable: %w", err)
		}
		spec, err := winservice.BuildSpec(winservice.Config{
			ExePath:   exe,
			Arguments: serviceArguments(o),
		})
		if err != nil {
			return err
		}
		if err := winservice.Install(spec); err != nil {
			return err
		}
		fmt.Printf("trstctl-agent: installed service %q (auto-start)\n", spec.Name)
		return nil
	case "uninstall":
		if err := winservice.Uninstall(winservice.DefaultServiceName); err != nil {
			return err
		}
		fmt.Printf("trstctl-agent: removed service %q\n", winservice.DefaultServiceName)
		return nil
	default:
		return fmt.Errorf("unknown --service action %q (want install | uninstall | run)", action)
	}
}
