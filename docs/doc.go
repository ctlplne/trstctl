// Package docs holds trstctl's documentation site (MkDocs Material) and the
// tests that hold the docs to the S7.6 acceptance criteria: the getting-started
// path matches the real product, install and uninstall are documented for every
// supported platform, internal links resolve, the MkDocs nav is consistent, and
// the authoring guides and references track the real CLI, configuration, and SDK
// surface rather than drifting from it.
//
// It contains no runtime code; the package exists so the documentation has a
// home and a test target in the module.
package docs
