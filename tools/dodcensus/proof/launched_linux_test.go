//go:build linux

// SPDX-License-Identifier: MPL-2.0

package proof

import (
	"net"
	"os"
	"testing"
)

func TestProcessLoopbackListenerRequiresDirectPIDOwnership(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	port := listener.Addr().(*net.TCPAddr).Port
	inode, err := processLoopbackListener(os.Getpid(), port)
	if err != nil || inode == "" {
		t.Fatalf("direct process listener was not witnessed: inode=%q err=%v", inode, err)
	}
	if inode, err := processLoopbackListener(os.Getpid()+1, port); err == nil || inode != "" {
		t.Fatalf("foreign PID inherited listener witness: inode=%q err=%v", inode, err)
	}
}
