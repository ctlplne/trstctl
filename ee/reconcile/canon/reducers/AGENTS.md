# AGENTS.md - ee/reconcile/canon/reducers

This package is proprietary XREC material under `LicenseRef-trstctl-EE`.

Rules:

- Keep every source file under this package tagged with `SPDX-License-Identifier: LicenseRef-trstctl-EE`.
- Reducers only translate read-only observed authority shapes into `canon.ObservedRecord`; they do not bypass `canon.ReduceTenant`.
- Observation credentials are read-only. Use `pluginhost.Grant` capabilities through the local observation sandbox; mutation attempts must return `connector.ErrDenied`.
- Secret values may appear only as `[]byte` native inputs long enough to prove discard/wipe behavior. They must never reach canonical attributes, digests, logs, errors, or strings.
- Self-plane observation must pass an explicit `tenant_id` into the projection reader.
- Do not import or touch PCAS succession-chain bridge semantics. XREC observes whole-estate credential state only.
