// SPDX-License-Identifier: BUSL-1.1

//go:build !wasip1

// Command module is the first-party connector module. It is meaningful only
// when built for wasip1 (see main_wasip1.go); on other targets it is empty so
// the package still builds with the rest of the tree.
package main

func main() {}
