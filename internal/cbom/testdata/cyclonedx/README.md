# CycloneDX 1.6 JSON schemas (test data)

These are the official CycloneDX specification schemas as shipped in
`github.com/CycloneDX/cyclonedx-go` v0.9.3 (`schema/`): `bom-1.6.schema.json`,
`spdx.schema.json`, and `jsf-0.82.schema.json` (named `jsf-0.82.schemax.json` there).
Copyright (c) OWASP Foundation, licensed under the Apache License 2.0. One change: their
`$comment` annotations are removed and the JSON is re-indented. `$comment` is a note for
people that JSON Schema validators ignore, so validation is unchanged; one upstream note
carried a debt marker that the repository's debt-marker guard would count as trstctl's own.

They exist only so the console test suite can validate trstctl's CBOM export
(`../cyclonedx-export.golden.json`) with an independent JSON Schema validator. Nothing in
the product reads them.
