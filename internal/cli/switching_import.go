// SPDX-License-Identifier: BUSL-1.1

package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
)

// `trstctl-cli switching import preview|apply` (A265): read another
// certificate-management product's export from a file, with an optional
// column map, and preview its mapping report or apply a reviewed digest.

const switchingExportLimit = 20 << 20

// switchingImportUsage prints the usage of one mode, or of both.
func switchingImportUsage(w io.Writer, mode string) {
	if mode != "apply" {
		_, _ = fmt.Fprintln(w, "Usage: trstctl switching import preview --file EXPORT [--column-map MAP.json]")
	}
	if mode != "preview" {
		_, _ = fmt.Fprintln(w, "Usage: trstctl switching import apply --file EXPORT [--column-map MAP.json] --name NAME --digest DIGEST")
	}
	_, _ = fmt.Fprintln(w, "\nEXPORT is the export's CSV (with a header row) or JSON text. MAP.json renames the export's own column names")
	_, _ = fmt.Fprintln(w, "to the switching fields, such as {\"Thumbprint\": \"fingerprint_sha256\", \"Valid To\": \"not_after\"}.")
	_, _ = fmt.Fprintln(w, "preview changes nothing: it prints every row's outcome counts, the rows worth reading, and the digest.")
	_, _ = fmt.Fprintln(w, "apply records exactly what that digest reviewed; a changed export or inventory refuses it.")
	if mode != "apply" {
		_, _ = fmt.Fprintln(w, "\nExample: trstctl switching import preview --file export.csv --column-map map.json")
	}
	if mode != "preview" {
		_, _ = fmt.Fprintln(w, "\nExample: trstctl switching import apply --file export.csv --column-map map.json --name \"region rollout\" --digest sha256:<digest>")
	}
}

func readSwitchingFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator names the export file to read (CWE-22 not applicable)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return data, nil
}

func runSwitchingImport(ctx context.Context, args []string, env Env, stdout, stderr io.Writer, server, token, tenant, caFile string) int {
	if len(args) == 0 || (args[0] != "preview" && args[0] != "apply") {
		switchingImportUsage(stderr, "")
		return 2
	}
	mode := args[0]
	fs := flag.NewFlagSet("trstctl-cli switching import "+mode, flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "the export file (CSV or JSON)")
	columnMap := fs.String("column-map", "", "a JSON file mapping the export's column names to switching fields")
	name := fs.String("name", "", "a name for the import (apply)")
	digest := fs.String("digest", "", "the digest of the preview you reviewed (apply)")
	fs.Usage = func() { switchingImportUsage(stderr, mode) }
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *file == "" || fs.NArg() != 0 || (mode == "apply" && (*name == "" || *digest == "")) {
		switchingImportUsage(stderr, mode)
		return 2
	}
	if server == "" {
		_, _ = fmt.Fprintln(stderr, "error: --server (or TRSTCTL_SERVER) is required")
		return 2
	}
	export, err := readSwitchingFile(*file, switchingExportLimit)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: export: %v\n", err)
		return 2
	}
	request := map[string]any{"export": string(export)}
	if *columnMap != "" {
		raw, err := readSwitchingFile(*columnMap, 1<<20)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: column map: %v\n", err)
			return 2
		}
		var m map[string]string
		if err := json.Unmarshal(raw, &m); err != nil {
			_, _ = fmt.Fprintf(stderr, "error: column map: %s is not a JSON object of column names to fields: %v\n", *columnMap, err)
			return 2
		}
		request["column_map"] = m
	}
	path, idem, want := "/api/v1/switching/imports/preview", "", http.StatusOK
	if mode == "apply" {
		request["name"], request["preview_digest"] = *name, *digest
		path, idem, want = "/api/v1/switching/imports", generateIdempotencyKey(), http.StatusCreated
	}
	body, err := json.Marshal(request)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	httpClient, err := httpClientForEnv(env, caFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: CA file: %v\n", err)
		return 2
	}
	status, out, err := do(ctx, httpClient, server, http.MethodPost, path, nil, body, token, tenant, idem, "")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %s: %v\n", mode, err)
		return 1
	}
	if status != want {
		_, _ = fmt.Fprintf(stderr, "error: %s: HTTP %d\n", mode, status)
		writeJSON(stderr, out)
		return 1
	}
	writeJSON(stdout, out)
	return 0
}
