// SPDX-License-Identifier: BUSL-1.1

// Command sdkpack builds the trstctl client SDKs into registry files and
// serves a directory of them as local registries (A250). It runs no other
// program: scripts/release/sdk-packages.sh runs npm pack and the JDK, and
// hands sdkpack their outputs.
//
//	sdkpack gomodule --files list --src clients/sdk/go --module trstctl.com/sdk/go --version v0.1.0 --out dir
//	sdkpack wheel    --files list --src clients/sdk/python --version 0.1.0 --out dir
//	sdkpack npm      --tarball trstctl-sdk-0.1.0.tgz --out dir
//	sdkpack maven    --jar sdk.jar --pom sdk.pom --group com.trstctl --artifact trstctl-sdk --version 0.1.0 --out dir
//	sdkpack serve    --dir dir --addr 127.0.0.1:8790
package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"trstctl.com/trstctl/tools/sdkpack/registry"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sdkpack:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: sdkpack gomodule|wheel|npm|maven|serve [flags]")
	}
	fs := flag.NewFlagSet("sdkpack "+args[0], flag.ContinueOnError)
	repo := fs.String("repo", ".", "the checkout the listed files are relative to")
	fileList := fs.String("files", "", "a file listing the tracked files to package (git ls-files output)")
	src := fs.String("src", "", "the SDK's directory in the checkout")
	module := fs.String("module", "", "the Go module path")
	version := fs.String("version", "", "the package version")
	at := fs.String("time", "", "the release time, RFC 3339 (default now)")
	out := fs.String("out", "", "the registry directory to write")
	tarball := fs.String("tarball", "", "the npm pack tarball")
	jar := fs.String("jar", "", "the built jar")
	pom := fs.String("pom", "", "the jar's pom, with its version")
	group := fs.String("group", "", "the Maven group ID")
	artifact := fs.String("artifact", "", "the Maven artifact ID")
	dir := fs.String("dir", "", "the registry directory to serve")
	addr := fs.String("addr", "127.0.0.1:8790", "the address to serve on")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	when := time.Now()
	if *at != "" {
		var err error
		if when, err = time.Parse(time.RFC3339, *at); err != nil {
			return fmt.Errorf("--time: %w", err)
		}
	}
	files := func() ([]string, error) {
		if *fileList == "" {
			return nil, errors.New("--files is required")
		}
		return registry.ReadFileList(*fileList)
	}
	var pkg registry.Package
	var err error
	switch args[0] {
	case "gomodule":
		var list []string
		if list, err = files(); err == nil {
			pkg, err = registry.GoModule(*repo, list, *src, *module, *version, when, *out)
		}
	case "wheel":
		var list []string
		if list, err = files(); err == nil {
			pkg, err = registry.Wheel(*repo, list, *src, *version, *out)
		}
	case "npm":
		pkg, err = registry.NPM(*tarball, *out)
	case "maven":
		pkg, err = registry.Maven(*jar, *pom, *group, *artifact, *version, when, *out)
	case "serve":
		return serve(*dir, *addr)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
	if err != nil {
		return err
	}
	if err := registry.AddToManifest(*out, strings.TrimPrefix(pkg.Version, "v"), pkg); err != nil {
		return err
	}
	fmt.Printf("%s %s %s sha256:%s\n", pkg.Ecosystem, pkg.Name, pkg.Version, pkg.SHA256)
	return nil
}

func serve(dir, addr string) error {
	if _, err := registry.ReadManifest(dir); err != nil {
		return fmt.Errorf("%s holds no built packages: %w", dir, err)
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	base := "http://" + l.Addr().String()
	fmt.Printf("serving %s as local registries: GOPROXY=%s/go  npm --registry %s/npm/  pip --index-url %s/pypi/simple/  maven %s/maven/\n",
		dir, base, base, base, base)
	srv := &http.Server{Handler: &registry.Handler{Dir: dir}, ReadHeaderTimeout: 10 * time.Second}
	return srv.Serve(l)
}
