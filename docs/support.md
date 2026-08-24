# Support and defect reporting

Use this page when the product behaves differently from its documentation or a
normal troubleshooting step does not recover it.

## Ordinary product defect

Repository access is required because the trstctl source repository is private
during this pre-1.0 design-partner stage. From an authenticated checkout, open a
bounded issue with GitHub CLI:

```bash
gh auth status
gh issue create --repo ctlplne/trstctl \
  --title "Defect: short description" \
  --body-file defect-report.md
```

Put only these items in `defect-report.md`:

1. the exact build version and source commit from **Trust Operations → System health**;
2. the page or command and the smallest safe reproduction sequence;
3. what you expected and what happened instead;
4. timestamps with timezone;
5. sanitized logs or a reviewed support bundle, never credentials or private keys.

If `gh auth status` fails or the repository refuses issue creation, use the named
support channel in the design-partner agreement. That access problem is external
to the running control plane; do not weaken trstctl authentication to work around
it.

## Possible security vulnerability

Do not open a normal issue and do not paste sensitive evidence into chat. Follow
the [private vulnerability reporting path](security/reporting.md). Preserve the
exact build identity and timestamps, but minimize copied tenant data.

## Build a safe diagnostic bundle

Run:

```bash
trstctl support-bundle --output trstctl-support.tar.gz --log-file ./control-plane.log
```

Review the archive before sharing it. The bundle is designed to exclude secrets
and live tenant rows by default, but the operator remains responsible for the
final handoff decision. See [Troubleshooting](troubleshooting.md) for the optional
aggregate enrollment-diagnostic addendum.
