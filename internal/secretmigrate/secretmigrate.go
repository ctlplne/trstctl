// SPDX-License-Identifier: BUSL-1.1

// Package secretmigrate reads secrets exported in common formats (dotenv,
// JSON, YAML) across environments and folders into the native store's names,
// references and metadata, and assesses a migration without putting a value
// in anything it returns (A243). It names formats, never products.
//
// A secret's native name is "<project>/<environment>/<folder…>/<key>". A
// reference in an exported value — ${NAME} (same folder), ${folder/NAME} (same
// environment) or ${environment:folder/NAME} — becomes the native
// ${secret.<name>}, so a chain of references stays a chain rather than being
// flattened into copies. Values are []byte from the first byte read and are
// wiped by Bundle.Wipe and Parsed.Wipe; the assessment carries names,
// metadata and actions only.
package secretmigrate

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secretjson"
)

// Formats a source may be in.
const (
	FormatDotenv = "dotenv"
	FormatJSON   = "json"
	FormatYAML   = "yaml"
)

// Limits on one bundle.
const (
	MaxSources     = 64
	MaxObjects     = 500
	MaxValueBytes  = 64 << 10
	maxSourceBytes = 4 << 20
	maxNameBytes   = 512
	maxMetaBytes   = 512
	maxTags        = 16
)

// Source is one exported file: the environment it belongs to, the folder its
// keys go under, its format and its bytes.
type Source struct {
	Environment string                 `json:"environment"`
	Folder      string                 `json:"folder,omitempty"`
	Format      string                 `json:"format"`
	Content     secretjson.StringBytes `json:"content"`
}

// Permission is an access grant the export carried: a subject's read, write
// or admin access to an environment, or to one folder of it.
type Permission struct {
	Subject     string `json:"subject"`
	Environment string `json:"environment"`
	Folder      string `json:"folder,omitempty"`
	Access      string `json:"access"`
}

// Consumer is an application expected to read the migrated secrets: its
// subject reading each listed key ("folder/KEY", or every key of the
// environment when none are listed) is the evidence that it moved.
type Consumer struct {
	Name        string   `json:"name"`
	Subject     string   `json:"subject"`
	Environment string   `json:"environment"`
	Secrets     []string `json:"secrets,omitempty"`
}

// Bundle is one migration's input: the destination project, the exported
// sources, and what the export said about access and consumers.
type Bundle struct {
	Project     string       `json:"project"`
	Sources     []Source     `json:"sources"`
	Permissions []Permission `json:"permissions,omitempty"`
	Consumers   []Consumer   `json:"consumers,omitempty"`
}

// Wipe zeroes every source's bytes.
func (b *Bundle) Wipe() {
	for i := range b.Sources {
		secret.Wipe(b.Sources[i].Content)
		b.Sources[i].Content = nil
	}
}

// Object is one exported secret.
type Object struct {
	Environment string
	Folder      string
	Key         string
	// Name is the native name: <project>/<environment>/<folder…>/<key>.
	Name string
	// Value is the value with its references translated; nil when the export
	// could not carry it (Exportable false).
	Value       []byte
	Exportable  bool
	Multiline   bool
	Description string
	Tags        []string
	Owner       string
	// References are the native names the value refers to.
	References []string
	// Location says where in the export it came from, never what it holds.
	Location string
}

// Unsupported is something in the export the migration cannot carry.
type Unsupported struct {
	Location string `json:"location"`
	Reason   string `json:"reason"`
}

// Parsed is a bundle read into objects.
type Parsed struct {
	Project     string
	Objects     []*Object
	Unsupported []Unsupported
}

// Wipe zeroes every object's value.
func (p *Parsed) Wipe() {
	for _, o := range p.Objects {
		secret.Wipe(o.Value)
		o.Value = nil
	}
}

var (
	slug       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	pathPart   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	keyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
)

// Parse reads every source of b. A malformed source is an error; an entry it
// cannot carry (an unusable key, a list where a value belongs, a value over
// the size limit, a duplicate name) is listed in Unsupported and skipped.
// The caller wipes the result.
func Parse(b *Bundle) (*Parsed, error) {
	if !slug.MatchString(b.Project) {
		return nil, errors.New("project is a lowercase slug (letters, digits, hyphens)")
	}
	if len(b.Sources) == 0 || len(b.Sources) > MaxSources {
		return nil, fmt.Errorf("a migration has 1 to %d sources", MaxSources)
	}
	out := &Parsed{Project: b.Project}
	seen := map[string]string{}
	for i, src := range b.Sources {
		if !slug.MatchString(src.Environment) {
			out.Wipe()
			return nil, fmt.Errorf("source %d: environment is a lowercase slug", i)
		}
		folder, ok := cleanFolder(src.Folder)
		if !ok {
			out.Wipe()
			return nil, fmt.Errorf("source %d: folder is slash-separated letters, digits, dots, hyphens and underscores", i)
		}
		if len(src.Content) > maxSourceBytes {
			out.Wipe()
			return nil, fmt.Errorf("source %d is larger than %d bytes", i, maxSourceBytes)
		}
		var entries []entry
		var err error
		switch src.Format {
		case FormatDotenv:
			entries, err = parseDotenv(src.Content)
		case FormatJSON:
			entries, err = parseJSON(src.Content)
		case FormatYAML:
			entries, err = parseYAML(src.Content)
		default:
			err = errors.New("format is dotenv, json or yaml")
		}
		if err != nil {
			out.Wipe()
			return nil, fmt.Errorf("source %d (%s, %s): %w", i, src.Environment, src.Format, err)
		}
		for j, e := range entries {
			location := fmt.Sprintf("%s:%s#%d", src.Environment, src.Format, j+1)
			if e.line > 0 {
				location = fmt.Sprintf("%s:%s:%d", src.Environment, src.Format, e.line)
			}
			o, reason := buildObject(b.Project, src.Environment, folder, e)
			if reason == "" {
				if prior, dup := seen[o.Name]; dup {
					reason = "the same name is also exported at " + prior
				}
			}
			if reason != "" {
				secret.Wipe(e.value)
				out.Unsupported = append(out.Unsupported, Unsupported{Location: location, Reason: reason})
				continue
			}
			o.Location = location
			seen[o.Name] = location
			out.Objects = append(out.Objects, o)
			if len(out.Objects) > MaxObjects {
				out.Wipe()
				return nil, fmt.Errorf("a migration carries at most %d secrets; split the export by environment or folder", MaxObjects)
			}
		}
	}
	translateReferences(out)
	sort.Slice(out.Objects, func(i, j int) bool { return out.Objects[i].Name < out.Objects[j].Name })
	return out, nil
}

// entry is one key the format parsers found, before naming.
type entry struct {
	folder      []string
	key         string
	value       []byte
	null        bool
	exportable  bool
	description string
	tags        []string
	owner       string
	line        int
	unsupported string
}

func buildObject(project, environment, folder string, e entry) (*Object, string) {
	if e.unsupported != "" {
		return nil, e.unsupported
	}
	parts := []string{}
	if folder != "" {
		parts = append(parts, strings.Split(folder, "/")...)
	}
	for _, p := range e.folder {
		if !pathPart.MatchString(p) {
			return nil, "a folder name is letters, digits, dots, hyphens and underscores"
		}
		parts = append(parts, p)
	}
	if !keyPattern.MatchString(e.key) {
		return nil, "a key is 1-128 letters, digits, dots, hyphens and underscores"
	}
	if len(e.value) > MaxValueBytes {
		return nil, fmt.Sprintf("the value is larger than %d bytes", MaxValueBytes)
	}
	if len(e.description) > maxMetaBytes || len(e.owner) > maxMetaBytes || len(e.tags) > maxTags {
		return nil, "the metadata is larger than the limit"
	}
	name := strings.Join(append(append([]string{project, environment}, parts...), e.key), "/")
	if len(name) > maxNameBytes {
		return nil, fmt.Sprintf("the name is longer than %d bytes", maxNameBytes)
	}
	o := &Object{
		Environment: environment, Folder: strings.Join(parts, "/"), Key: e.key, Name: name,
		Exportable: e.exportable && !e.null, Description: e.description, Tags: e.tags, Owner: e.owner,
	}
	if o.Exportable {
		o.Value = e.value
		o.Multiline = bytes.IndexByte(o.Value, '\n') >= 0
	} else {
		secret.Wipe(e.value)
	}
	return o, ""
}

// cleanFolder normalizes a source's folder: slash-separated parts, no empty,
// "." or ".." part.
func cleanFolder(folder string) (string, bool) {
	folder = strings.Trim(folder, "/")
	if folder == "" {
		return "", true
	}
	for _, p := range strings.Split(folder, "/") {
		if p == "." || p == ".." || !pathPart.MatchString(p) {
			return "", false
		}
	}
	return folder, true
}

// NativeName is the native name of key in folder of environment.
func NativeName(project, environment, folder, key string) string {
	if folder == "" {
		return project + "/" + environment + "/" + key
	}
	return project + "/" + environment + "/" + folder + "/" + key
}
