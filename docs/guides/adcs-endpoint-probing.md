# Probe AD CS enrollment endpoints from directory hostnames

This opt-in read checks Web Enrollment and NDES client paths on CA hostnames
published in LDAP. It keeps candidate origin, HTTP results and page coverage so
an operator can distinguish an unattempted target from a response. A response
proves reachability at that time; it does not prove enrollment or IIS hardening.

## Configure and preview

Keep the normal AD CS directory reader and vaulted password reference. Upgrade
the exact selected network-role relay, enable `--relay-claim`, and allow
`adcs.inventory.endpoint_probe` in the server's
`agent_channel.claimable_job_kinds`. Preflight requires its fresh authenticated
enabled executor census. An older relay cannot silently ignore the option.

In Discovery, choose Microsoft AD CS, configure the directory and reader,
select the relay, then enable **Probe enrollment paths from directory hostnames**.
Enter 1..32 DNS suffixes such as `corp.example`. A candidate must be the suffix
itself or a subdomain at a label boundary. Hostnames must be ASCII DNS names;
addresses, ports, URL syntax, wildcards and foreign suffixes are refused.

Example public source configuration:

```json
{
  "name": "corp-adcs-endpoints",
  "kind": "adcs",
  "config": {
    "url": "ldaps://dc01.corp.example:636",
    "configuration_dn": "CN=Configuration,DC=corp,DC=example",
    "bind_dn": "CN=reader,OU=Service Accounts,DC=corp,DC=example",
    "password_ref": "secret://adcs/domain-reader",
    "relay_agent_id": "11111111-1111-4111-8111-111111111111",
    "endpoint_probe": {"enabled": true, "dns_suffixes": ["corp.example"]},
    "allow_private_endpoint": true,
    "private_egress_cidrs": ["10.42.8.0/24"]
  }
}
```

Replace the example relay UUID and CIDR with owned destinations. Private egress
requires its existing permission, the source grant and the relay's local grant.
The always-on address guard still refuses metadata, link-local and loopback.
Directory data cannot grant destinations. The directory's lab-only
`insecure_skip_verify` option never disables HTTPS verification for probes.

Save the JSON as `adcs-source.json`. Use `trstctl-cli discovery sources create -f
adcs-source.json`, then `trstctl-cli discovery sources preflight <source-id>`.
The preview performs no DNS, directory or HTTP read. Its zero resolved targets
means the LDAP candidates are not known yet, rather than an empty estate.
Start with `trstctl-cli discovery runs start -f run.json`, where `run.json` is
`{"source_id":"<source-id>"}`. Inspect `discovery runs get <run-id>` and
`posture adcs`; configure a discovery schedule for continuing reads.

## Read and recover the evidence

For each LDAP enrollment service, the relay derives HTTP and HTTPS variants of
`/certsrv/` and `/certsrv/mscep/mscep.dll`. It never automatically fetches
`mscep_admin`. An operator may still configure explicit targets, including a
separately hosted NDES service. A configured/generated duplicate runs once,
retaining `configured_and_ldap_dns` origin; other origins are `configured` and
`ldap_dns`. Published CES URIs remain separate LDAP metadata.

A canonical plan digest binds the service/target tuples and hostname issues.
Each job represents at most 24 targets with four workers, a five-second target
deadline and a 90-second overall budget. LDAP sub-budgets remain bounded. It
sends no password, authentication header or cookie, follows no redirect, requests
one byte from cooperative servers and closes bodies without reading them.
Only authentication scheme names survive; challenges, cookies, redirect
locations and body content do not. Response headers are bounded to 64 KiB.

The latest page records total targets, current offset, next offset, hostname
issues and each service's place on the page. `complete` means the whole plan is
represented in this one page without hostname issues. It is not a successful
enrollment or a verified HTTP result. Inspect every endpoint state. Cancellation
before an attempt is `not_checked` with `deadline_or_cancellation`; a failed
connection, refused destination or TLS failure is `unreachable` and unverified.
Partial or unverified assessments raise `ADCS-ENDPOINT-PROBE-INCOMPLETE`.

The next manual or scheduled run uses the prior retained observation's next
offset. A directory-read failure preserves the requested cursor, a changed
canonical plan resets to zero, and the last page wraps to zero. Never supply a
cursor in source configuration; it is accepted only in the immutable queued
command. Prior pages keep their own timestamps in history. The current view
shows the latest page and does not merge old results into a simultaneous estate
assessment. The bounded service view flags its 500-row ceiling when reached;
retained observations preserve all reported services within the 512-service
LDAP bound. Restore retained history and replay if source-bound evidence is
unavailable or differs from its projection.

## Verification boundary

`TestADCSLDAPEndpointProbeRealNetworkStandin` is the opt-in Linux private-network
proof. It reads public configuration from `TRSTCTL_ADCS_PROBE_NETWORK_CONFIG`,
the owned reader file from `TRSTCTL_ADCS_PROBE_PASSWORD_FILE`, public request
audit from `TRSTCTL_ADCS_PROBE_HTTP_AUDIT`, and can write public report evidence
to `TRSTCTL_ADCS_PROBE_REPORT`. The fixture uses real Samba and private HTTP/TLS
listeners; it exercises the production collector and address checks. Unit and
served tests separately cover paging, cancellation, immutable command/receipt
binding, failed-page retry, tenant isolation, projection tampering and replay.

This does not qualify Windows IIS authentication, actual NDES SCEP enrollment,
EPA/channel binding, a real AD forest or Windows-native runtime behavior. Those
checks require the Windows lab. Microsoft documents the distinct
[NDES client path](https://learn.microsoft.com/en-us/troubleshoot/mem/intune/certificates/troubleshoot-scep-certificate-device-to-ndes)
and [NDES role](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/network-device-enrollment-service-overview).
