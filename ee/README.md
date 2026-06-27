# trstctl EE Fence

Commercial trstctl code lives under `ee/`.

Boundary rules:

- Core must not import `trstctl.com/trstctl/ee`, except from `cmd/trstctl/ee_attach.go`.
- `cmd/trstctl/ee_attach.go` must carry `//go:build !trstctl_core`.
- The `trstctl_core` build uses `cmd/trstctl/ee_attach_core.go` and links zero `ee/` packages.

Multi-tenancy, the event spine, the crypto boundary, audit/export rights, and the license verifier stay in core.
