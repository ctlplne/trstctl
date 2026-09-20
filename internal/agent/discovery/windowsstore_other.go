// SPDX-License-Identifier: BUSL-1.1

//go:build !windows

package discovery

import "context"

// platformWindowsCertReader on a platform that has no Windows certificate store.
//
// It fails rather than returning nothing. An empty result would tell an operator
// running a Linux agent that their Windows estate is clean, which is precisely
// the false comfort epic C1 exists to remove — and it would be worse than the
// original defect, because it would arrive with the authority of an actual scan.
func platformWindowsCertReader() windowsCertReader { return unsupportedWindowsReader{} }

type unsupportedWindowsReader struct{}

func (unsupportedWindowsReader) readStore(context.Context, WindowsStoreLocation, string) (map[string][]byte, error) {
	return nil, ErrWindowsStoreUnsupported
}
