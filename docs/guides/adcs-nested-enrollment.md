# Read nested AD CS enrollment links

This read shows users and computers that reach a template’s enrollment trustee
through observed security groups. It keeps the path, canonical Windows SIDs and
read time so you can check the result in your directory. It does not perform
Windows AccessCheck or authorize certificate issuance.

## Configure and preview

Use a least-privilege directory reader that can read the template DACL and the
named membership attributes: `objectSid`, `objectClass`, `groupType`, `member`
and `memberOf`. Keep its password in the secret vault and configure only its
`secret://` reference. The relay must trust the directory’s TLS certificate.
Plain LDAP is upgraded with StartTLS before any bind; a refusal stops the read.
`insecure_skip_verify` is an explicit lab-only override and produces unverified
directory evidence.

Upgrade the selected network-role relay and start it with `--relay-claim`.
Enable `adcs.inventory.enrollment_groups` in the server’s
`agent_channel.claimable_job_kinds`. Saving a source performs no directory I/O;
preflight and run admission require the exact relay to report a fresh enabled
executor census for this job kind. Restore its heartbeat, enable the missing
flag or upgrade the binary when the preview names that blocker.

In Discovery, choose Microsoft AD CS, enter its directory authority,
configuration naming context and vaulted bind reference, select the relay,
then enable **Read nested enrollment groups**. Enter the explicit domain naming
context, such as `DC=corp,DC=example`. Preview, review and save. The CLI supports
the same flow:

```json
{
  "name": "corp-adcs-nested",
  "kind": "adcs",
  "config": {
    "url": "ldaps://dc01.corp.example:636",
    "configuration_dn": "CN=Configuration,DC=corp,DC=example",
    "bind_dn": "CN=trstctl-reader,OU=Service Accounts,DC=corp,DC=example",
    "password_ref": "secret://adcs/domain-reader",
    "relay_agent_id": "11111111-1111-4111-8111-111111111111",
    "nested_groups_enabled": true,
    "membership_domain_dn": "DC=corp,DC=example"
  }
}
```

Use your enrolled relay UUID in place of the example. Save this public
configuration as `adcs-source.json`, then:

```sh
trstctl-cli discovery sources create -f adcs-source.json
trstctl-cli discovery sources preflight <source-id>
```

Start a run with `discovery runs start -f run.json`, where `run.json` contains
`{"source_id":"<source-id>"}`. Use `discovery runs get <run-id>` for its execution
state and `posture adcs` for the actual directory evidence. Configure a discovery
schedule for subsequent reads. A completed read and complete membership evidence
are separate facts: inspect each template’s `enrollment_membership.state`.

## Interpret and recover

Posture keeps direct DACL trustees separate from nested member paths. A complete
account-visible link read has `state: complete`, its domain and time, and a path
such as user → inner security group → outer enrollment trustee. Every raw grant
and deny trustee is accounted for. Direct and expanded denies suppress a grant;
this is conservative link analysis, rather than evaluation of ACE ordering in a
Windows token. The existing template risk classification does not guess that an
unknown custom SID is low privilege.

The LDAP in-chain OID is `1.2.840.113556.1.4.1941`. A known direct member must also
appear in its transitive query, with the corresponding parent link, before the
reader calls a group complete. An unsupported filter returning no rows does not
prove empty access. A critical domain-scope control keeps searches within the
single configured naming context. Referrals are refused and never followed.
Microsoft documents the [transitive rule](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1e889adc-b503-4423-8985-c28d5c7d4887)
and [single-partition control](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/ldap-server-domain-scope-oid).

An unreadable or unresolved trustee, unconfirmed matching rule, distribution-only
path, missing/ranged link, conditional permission ACE or exhausted query/report
budget produces incomplete evidence and no verified member list. Check the
closed trustee reason and the selected relay’s access and reach, then run the
source again. Empty groups without a readable positive control remain
unassessed. A failed read does not prove a user lost enrollment rights.

The read is bounded to 256 membership queries, 4,096 returned nodes, 1,024
matched descendants per trustee, 16 path nodes and 256 KiB of membership
attributes. Membership evidence has a 384 KiB aggregate serialization limit;
affected templates explicitly report `budget_exceeded`, and exhaustion that
cannot fit that outcome fails the run. Authentication is bounded to 20 seconds,
LDAP requests to 20 seconds, nested collection to 45 seconds, and the complete
relay attempt to 60 seconds. The stream rejects frames above 2 MiB and totals
above 16 MiB before the directory library allocates their declared bodies.

## Proof boundary

The served integration test `TestServedADCSNestedEnrollmentAgainstSamba` accepts
an owned Samba fixture through `TRSTCTL_ADCS_SAMBA_FIXTURE`, its password file
through `TRSTCTL_ADCS_SAMBA_PASSWORD_FILE`, and its authority through
`TRSTCTL_ADCS_SAMBA_URL`. Public fixture metadata names `domain_dn`,
`configuration_dn`, `bind_dn`, `user_dn`, `user_sid`, `inner_dn`, `outer_dn` and
`template`. Password contents never belong in that metadata. Provision a
separate reader, user → inner → outer security groups, and a template granting
Certificate-Enrollment to outer before running the test. The production reader
performs Bind/Search only; fixture administration is separate.

Focused qualification used Samba AD 4.15.13. It verifies actual matching-rule
results, the source API, per-attempt vaulted bind, mTLS relay job, signed receipt,
CLI/API readback, isolation and projection replay. A lab TLS override does not
qualify directory identity. Conditional ACEs, primary groups, SID history,
cross-forest tokens and full Windows AccessCheck remain unassessed. A licensed
Windows forest, its directory audit and trusted production TLS require separate
release-lab qualification.
