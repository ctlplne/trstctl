// SPDX-License-Identifier: MPL-2.0

//go:build !linux

package proof

import "fmt"

type artifactMutationWatch struct{}

func newArtifactMutationWatch(string) (*artifactMutationWatch, error) {
	return nil, fmt.Errorf("shipped-artifact mutation watch requires Linux inotify")
}

func (w *artifactMutationWatch) AssertQuiet() error {
	return fmt.Errorf("shipped-artifact mutation watch requires Linux inotify")
}

func (w *artifactMutationWatch) Close() error { return nil }
