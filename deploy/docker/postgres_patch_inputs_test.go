// SPDX-License-Identifier: BUSL-1.1

package docker

import (
	"strings"
	"testing"
)

// The base image supplies the unchanged dependency closure. Only these six
// public package blobs may be added, and installation has no network access.
func assertPostgresPatchConstruction(t *testing.T, df string) {
	t.Helper()
	for _, problem := range postgresPatchConstructionErrors(df) {
		t.Error(problem)
	}
}

func postgresPatchConstructionErrors(df string) []string {
	var problems []string
	required := []string{
		"ARG TARGETARCH",
		"FROM scratch AS patches",
		"COPY --from=patches /${TARGETARCH}/ /tmp/trstctl-postgres-patches/",
		"RUN --network=none apk add --no-network /tmp/trstctl-postgres-patches/*.apk",
		"&& rm -rf /tmp/trstctl-postgres-patches",
		"ADD --checksum=sha256:161223a16f042b8e469e9441291e071464fd91d4f4bbe6f496ee8d0abd4e0701 https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/libcrypto3-3.5.8-r0.apk /amd64/libcrypto3-3.5.8-r0.apk",
		"ADD --checksum=sha256:aca521e5ae4a321322a9d47ed64a1775f5ab1ffd215d1e9fc0433c58f7bfd037 https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/libssl3-3.5.8-r0.apk /amd64/libssl3-3.5.8-r0.apk",
		"ADD --checksum=sha256:8306e5bb577696c9069fe1dfd9e1dcc39d2d481c6a1b0e707fd03c3e21aa6aa2 https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/libuuid-2.42.3-r1.apk /amd64/libuuid-2.42.3-r1.apk",
		"ADD --checksum=sha256:35b892813c23664a3592e4fc8c12a03538a22c579057655361c7043305272a9a https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/libcrypto3-3.5.8-r0.apk /arm64/libcrypto3-3.5.8-r0.apk",
		"ADD --checksum=sha256:d6ec970cc10e01539e41626f720c4e0ac69016eaa2079a10ef776ffd3243db5b https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/libssl3-3.5.8-r0.apk /arm64/libssl3-3.5.8-r0.apk",
		"ADD --checksum=sha256:9ce20c7ffe2ccaa7c321893c10564abbca13c3f2edb82f60a35f1f68e004f86c https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/libuuid-2.42.3-r1.apk /arm64/libuuid-2.42.3-r1.apk",
	}
	for _, want := range required {
		if !strings.Contains(df, want) {
			problems = append(problems, "missing immutable PostgreSQL package construction: "+want)
		}
	}
	if strings.Count(df, "ADD ") != 6 || strings.Count(df, "COPY ") != 1 || strings.Count(df, " apk add ") != 1 {
		problems = append(problems, "unexpected PostgreSQL package input or installation command")
	}
	for _, line := range strings.Split(df, "\n") {
		if strings.HasPrefix(line, "RUN ") && line != `RUN --network=none apk add --no-network /tmp/trstctl-postgres-patches/*.apk \` && line != "RUN rm -f /usr/local/bin/gosu && test ! -e /usr/local/bin/gosu" {
			problems = append(problems, "unreviewed PostgreSQL runtime construction: "+line)
		}
	}
	return problems
}

func TestPostgresPatchConstructionRejectsMutableInputs(t *testing.T) {
	df := readArtifact(t, "Dockerfile.postgres")
	if problems := postgresPatchConstructionErrors(df); len(problems) != 0 {
		t.Fatal(problems)
	}
	for name, changed := range map[string]string{
		"network install": strings.Replace(df, "RUN --network=none apk add --no-network", "RUN apk add --no-cache", 1),
		"unpinned input":  strings.Replace(df, "ADD --checksum=sha256:", "ADD --checksum=sha512:", 1),
		"changed package": strings.Replace(df, "libuuid-2.42.3-r1.apk", "libuuid-2.42.3-r2.apk", 1),
		"extra install":   df + "\nRUN apk upgrade\n",
	} {
		t.Run(name, func(t *testing.T) {
			if len(postgresPatchConstructionErrors(changed)) == 0 {
				t.Fatal("mutable or changed package construction accepted")
			}
		})
	}
}
