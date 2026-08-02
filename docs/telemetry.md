# Telemetry (opt-in, off by default)

trstctl can send a small amount of anonymized usage data to a collector that you
name. **It is off by default and never sends anything unless you explicitly turn
it on.** This is a decided, privacy-first position for a self-hosted product used
in regulated environments.

The project operates no public telemetry collector, and trstctl ships no default
endpoint. The setting exists so an operator running a fleet can aggregate their
own coarse usage counts. If you turn telemetry on you must point it at an
`https` collector you run, and trstctl refuses to start if you do not.

## What is sent (only when enabled)

A single JSON document, at most once per interval:

```json
{
  "schema": 1,
  "instance_id": "9f2c…",          // random, generated once, never host-derived
  "version": "v1.2.3",
  "os": "linux",
  "arch": "amd64",
  "credential_buckets": {            // counts BUCKETED into coarse ranges by type
    "x509_certificate": "101-1000",
    "ssh_key": "1-10"
  }
}
```

- **`instance_id`** — a random 128-bit identifier generated on first use and
  stored locally. It is not derived from your hostname, IP, MAC, organization, or
  any credential. The receiver counts distinct IDs to estimate active
  deployments; that figure is treated as a lower bound.
- **`credential_buckets`** — how many credentials of each *type* you manage,
  reported as a coarse range (`0`, `1-10`, `11-100`, `101-1000`, `1001-10000`,
  `10000+`). Exact counts never leave the process.

## What is never sent

No credential content or metadata of any kind: no subjects, SANs, serials,
fingerprints, public keys, or expiry dates. No owner identities, emails, team
names, hostnames, IP addresses, file paths, CA names, or connector targets. No
configuration values. If a field could identify you or your credentials, it is
not in the payload — by construction, the payload struct has no place to put it.

## How to opt in

Telemetry is enabled only when you set it explicitly, and you must supply the
collector yourself — there is no default endpoint to fall back on:

```bash
# environment
export TRSTCTL_TELEMETRY_ENABLED=true
# required: an https collector you operate
export TRSTCTL_TELEMETRY_ENDPOINT=https://telemetry.internal.example/v1/usage
# optional overrides
export TRSTCTL_TELEMETRY_INTERVAL=24h
export TRSTCTL_TELEMETRY_INSTANCE_ID_FILE=/data/telemetry/instance-id
```

or in the config file:

```json
{ "telemetry": { "enabled": true, "endpoint": "https://telemetry.internal.example/v1/usage", "interval": "24h" } }
```

When enabled, the endpoint is required and must be an absolute `https://` URL,
and the interval a positive Go duration. Enabling telemetry without an endpoint
fails validation with `telemetry.endpoint is required` — a startup error, never
a silent no-op that posts into the void.
`TRSTCTL_TELEMETRY_INSTANCE_ID_FILE` must name a writable local file for the
random anonymous instance ID. trstctl validates this on boot and refuses to
start on a bad telemetry configuration. A typo in `TRSTCTL_TELEMETRY_ENABLED`
(anything that is not a recognized boolean) is ignored and leaves telemetry
**off**.

Air-gapped installs are stricter: when `TRSTCTL_AIRGAP_ENABLED=true`, trstctl
refuses to start with `TRSTCTL_TELEMETRY_ENABLED=true`. That turns "off by
default" into "off by policy" for disconnected environments. See
[Air-gapped install](airgap.md) for the no-phone-home runtime guard and Helm
overlay.

## Verifying the current setting

```bash
trstctl -check-config | grep telemetry
# telemetry.enabled: false
```

## How to opt out

Do nothing — it is already off. If you previously enabled it, set
`TRSTCTL_TELEMETRY_ENABLED=false` (or remove the config key) and restart. You may
also delete the stored `instance_id` file; a new random ID is generated only if
you opt in again.
