// SPDX-License-Identifier: MPL-2.0

// Command trstctl-ksp-register registers trstctl-ksp.dll with Windows CNG as
// the trstctl Key Storage Provider, so signtool and other CNG signing tools
// open it by name, and removes it again. Run it from an elevated prompt:
//
//	trstctl-ksp-register install path\to\trstctl-ksp.dll
//	trstctl-ksp-register status
//	trstctl-ksp-register uninstall
//
// install copies the DLL into System32, where only administrators can replace
// it, and registers that image for CNG's key storage interface; status reports
// whether CNG and NCrypt list the provider and exits 1 when they do not;
// uninstall removes the registration and the copied DLL.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"trstctl.com/clients/signing/internal/kspinfo"
)

// cng is the CNG configuration the commands change: the Windows build calls
// bcrypt.dll and ncrypt.dll; elsewhere every call fails.
type cng interface {
	systemDirectory() (string, error)
	register(image string) error
	unregister() error
	// listed reports whether CNG has the provider registered and whether
	// NCrypt lists it among the key storage providers.
	listed() (registered, storage bool, err error)
}

var errNotWindows = errors.New("trstctl-ksp-register configures Windows CNG; run it on Windows")

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, platform{})) }

func run(args []string, stdout, stderr io.Writer, c cng) int {
	usage := func() int {
		fmt.Fprintln(stderr, "usage: trstctl-ksp-register install <trstctl-ksp.dll> | status | uninstall")
		return 2
	}
	if len(args) == 0 {
		return usage()
	}
	var err error
	switch {
	case args[0] == "install" && len(args) == 2:
		err = install(c, args[1], stdout)
	case args[0] == "uninstall" && len(args) == 1:
		err = uninstall(c, stdout)
	case args[0] == "status" && len(args) == 1:
		var ok bool
		if ok, err = status(c, stdout); err == nil && !ok {
			return 1
		}
	default:
		return usage()
	}
	if err != nil {
		fmt.Fprintf(stderr, "trstctl-ksp-register: %v\n", err)
		return 1
	}
	return 0
}

// install copies the provider into the system directory and registers it.
func install(c cng, dll string, out io.Writer) error {
	dir, err := c.systemDirectory()
	if err != nil {
		return err
	}
	image, err := os.ReadFile(dll) // #nosec G304 -- the administrator names the DLL to install
	if err != nil {
		return fmt.Errorf("read the provider DLL: %w", err)
	}
	if !bytes.HasPrefix(image, []byte("MZ")) {
		return fmt.Errorf("%s is not a Windows DLL", dll)
	}
	target := filepath.Join(dir, kspinfo.ImageName)
	if !samePath(dll, target) {
		if err := os.WriteFile(target, image, 0o644); err != nil { // #nosec G306 -- System32 images are world-readable; only administrators write there
			return fmt.Errorf("copy the provider into %s (close programs that loaded it): %w", dir, err)
		}
	}
	if err := c.register(kspinfo.ImageName); err != nil {
		return err
	}
	fmt.Fprintf(out, "registered %q as %s\n", kspinfo.ProviderName, target)
	return nil
}

// uninstall removes the registration, then the copied DLL.
func uninstall(c cng, out io.Writer) error {
	if err := c.unregister(); err != nil {
		return err
	}
	dir, err := c.systemDirectory()
	if err != nil {
		return err
	}
	target := filepath.Join(dir, kspinfo.ImageName)
	if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("the registration is removed; delete %s once no program has it loaded: %w", target, err)
	}
	fmt.Fprintf(out, "removed %q\n", kspinfo.ProviderName)
	return nil
}

// status prints what CNG and NCrypt list and reports whether the provider is
// usable by name.
func status(c cng, out io.Writer) (bool, error) {
	registered, storage, err := c.listed()
	if err != nil {
		return false, err
	}
	fmt.Fprintf(out, "%s: registered with CNG: %t; listed by NCrypt: %t\n", kspinfo.ProviderName, registered, storage)
	return registered && storage, nil
}

func samePath(a, b string) bool {
	x, errA := filepath.Abs(a)
	y, errB := filepath.Abs(b)
	return errA == nil && errB == nil && strings.EqualFold(filepath.Clean(x), filepath.Clean(y))
}
