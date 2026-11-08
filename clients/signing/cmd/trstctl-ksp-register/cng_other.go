// SPDX-License-Identifier: MPL-2.0

//go:build !windows

package main

// platform refuses everything off Windows: there is no CNG to configure.
type platform struct{}

func (platform) systemDirectory() (string, error) { return "", errNotWindows }
func (platform) register(string) error            { return errNotWindows }
func (platform) unregister() error                { return errNotWindows }
func (platform) listed() (bool, bool, error)      { return false, false, errNotWindows }
