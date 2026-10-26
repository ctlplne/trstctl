// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"trstctl.com/trstctl/internal/agent/csitrust"
	"trstctl.com/trstctl/internal/agent/k8s"
	"trstctl.com/trstctl/internal/buildinfo"
)

// runCSITrust serves the trust.csi.trstctl.com node plugin on socketPath until
// ctx ends. The node id is NODE_NAME from the downward API, as the shipped
// DaemonSet sets it.
func runCSITrust(ctx context.Context, socketPath string) error {
	client, err := k8s.InCluster()
	if err != nil {
		return err
	}
	node := strings.TrimSpace(os.Getenv("NODE_NAME"))
	if node == "" {
		if node, err = os.Hostname(); err != nil || node == "" {
			return fmt.Errorf("CSI trust driver needs NODE_NAME (the downward API spec.nodeName)")
		}
	}
	fmt.Printf("trstctl-agent: serving %s on %s for node %s\n", csitrust.DriverName, socketPath, node)
	return csitrust.NewDriver(client, node, buildinfo.Version()).Serve(ctx, socketPath)
}
