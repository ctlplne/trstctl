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
		"ADD --checksum=sha256:6632d758d8f5e9ea3b650fe966f23bbf9a202f8b8dceecac93da135dec5e3689 https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/libcrypto3-3.5.9-r0.apk /amd64/libcrypto3-3.5.9-r0.apk",
		"ADD --checksum=sha256:05e3393fb95aa5751ca2f9d242f659f6cff82c1cc7767cc2df4a086f7ad01877 https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/libssl3-3.5.9-r0.apk /amd64/libssl3-3.5.9-r0.apk",
		"ADD --checksum=sha256:8306e5bb577696c9069fe1dfd9e1dcc39d2d481c6a1b0e707fd03c3e21aa6aa2 https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/libuuid-2.42.3-r1.apk /amd64/libuuid-2.42.3-r1.apk",
		"ADD --checksum=sha256:2676a2b0b6e23ea2edccf3ee982b9842a665d52603d047de3d0a185dc316d983 https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/libcrypto3-3.5.9-r0.apk /arm64/libcrypto3-3.5.9-r0.apk",
		"ADD --checksum=sha256:20ac252b276d73f2c69c1d25f84537c7fba81caefc026c6be1094b394af2082e https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/libssl3-3.5.9-r0.apk /arm64/libssl3-3.5.9-r0.apk",
		"ADD --checksum=sha256:9ce20c7ffe2ccaa7c321893c10564abbca13c3f2edb82f60a35f1f68e004f86c https://dl-cdn.alpinelinux.org/alpine/v3.24/main/aarch64/libuuid-2.42.3-r1.apk /arm64/libuuid-2.42.3-r1.apk",
		// The trust store (eMudhra response, Part 1): one pinned Alpine bundle
		// package, filtered by the shipped distrust list in a Go build stage,
		// copied over the base image's bundle. Reviewed construction, no
		// network at install time, no other trust input.
		"FROM scratch AS trust-source",
		"ADD --checksum=sha256:bb008f6d214b6af7576324659856fb63dc8dcb4373f8345ff706388696f1254d https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/ca-certificates-bundle-20261020-r0.apk /ca-certificates-bundle-20261020-r0.apk",
		"COPY --from=trust-source /ca-certificates-bundle-20261020-r0.apk /tmp/trust/ca-certificates-bundle.apk",
		"trstctl-trustbundle filter -in /tmp/trust/ca-certificates-bundle.apk -out /out/trust/ca-certificates.crt -report /out/trust/report.json -expect 118",
		"COPY --from=trust /out/trust/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt",
	}
	for _, want := range required {
		if !strings.Contains(df, want) {
			problems = append(problems, "missing immutable PostgreSQL package construction: "+want)
		}
	}
	if strings.Count(df, "ADD ") != 7 || strings.Count(df, "COPY ") != 6 || strings.Count(df, " apk add ") != 1 {
		problems = append(problems, "unexpected PostgreSQL package input or installation command")
	}
	for _, line := range strings.Split(df, "\n") {
		if strings.HasPrefix(line, "RUN ") && line != `RUN --network=none apk add --no-network /tmp/trstctl-postgres-patches/*.apk \` && line != "RUN rm -f /usr/local/bin/gosu && test ! -e /usr/local/bin/gosu" && line != `RUN mkdir -p /out/trust \` {
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
