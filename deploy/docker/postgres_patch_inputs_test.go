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
		"COPY internal/crypto/crewjamsaml/go.mod internal/crypto/crewjamsaml/go.sum ./internal/crypto/crewjamsaml/",
		"FROM scratch AS patches",
		// TOOL-O1: each fetching stage takes its base from ALPINE_MIRROR, the
		// Alpine CDN by default; the checksums hold whichever serves them.
		"ARG ALPINE_MIRROR=https://dl-cdn.alpinelinux.org/alpine",
		"COPY --from=patches /${TARGETARCH}/ /tmp/trstctl-postgres-patches/",
		"RUN --network=none apk add --no-network /tmp/trstctl-postgres-patches/*.apk",
		"&& rm -rf /tmp/trstctl-postgres-patches",
		"ADD --checksum=sha256:042026082cc9bc7872d1baa81755c50efa70b05f03b5369fdc5f0a1303009720 ${ALPINE_MIRROR}/v3.24/main/x86_64/libcrypto3-3.5.9-r1.apk /amd64/libcrypto3-3.5.9-r1.apk",
		"ADD --checksum=sha256:18c5778cbe52e1991303f8531970b05d4e6e036ea08349322f7422f42a689dc7 ${ALPINE_MIRROR}/v3.24/main/x86_64/libssl3-3.5.9-r1.apk /amd64/libssl3-3.5.9-r1.apk",
		"ADD --checksum=sha256:8306e5bb577696c9069fe1dfd9e1dcc39d2d481c6a1b0e707fd03c3e21aa6aa2 ${ALPINE_MIRROR}/v3.24/main/x86_64/libuuid-2.42.3-r1.apk /amd64/libuuid-2.42.3-r1.apk",
		"ADD --checksum=sha256:58ea027d8bd64fffac7d2106a9034341d6735387298a5e01b551429c73a13c71 ${ALPINE_MIRROR}/v3.24/main/aarch64/libcrypto3-3.5.9-r1.apk /arm64/libcrypto3-3.5.9-r1.apk",
		"ADD --checksum=sha256:4aff30f84e7ac922b026f8b2dd574d91bb3bb01d22767a8a9a0a10c5ef64a44b ${ALPINE_MIRROR}/v3.24/main/aarch64/libssl3-3.5.9-r1.apk /arm64/libssl3-3.5.9-r1.apk",
		"ADD --checksum=sha256:9ce20c7ffe2ccaa7c321893c10564abbca13c3f2edb82f60a35f1f68e004f86c ${ALPINE_MIRROR}/v3.24/main/aarch64/libuuid-2.42.3-r1.apk /arm64/libuuid-2.42.3-r1.apk",
		// The trust store (eMudhra response, Part 1): one pinned Alpine bundle
		// package, filtered by the shipped distrust list in a Go build stage,
		// copied over the base image's bundle. Reviewed construction, no
		// network at install time, no other trust input.
		"FROM scratch AS trust-source",
		"ADD --checksum=sha256:bb008f6d214b6af7576324659856fb63dc8dcb4373f8345ff706388696f1254d ${ALPINE_MIRROR}/v3.24/main/x86_64/ca-certificates-bundle-20261020-r0.apk /ca-certificates-bundle-20261020-r0.apk",
		"COPY --from=trust-source /ca-certificates-bundle-20261020-r0.apk /tmp/trust/ca-certificates-bundle.apk",
		"trstctl-trustbundle filter -in /tmp/trust/ca-certificates-bundle.apk -out /out/trust/ca-certificates.crt -report /out/trust/report.json -expect 118",
		"COPY --from=trust /out/trust/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt",
	}
	for _, want := range required {
		if !strings.Contains(df, want) {
			problems = append(problems, "missing immutable PostgreSQL package construction: "+want)
		}
	}
	if strings.Count(df, "ADD ") != 7 || strings.Count(df, "COPY ") != 7 || strings.Count(df, " apk add ") != 1 {
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
