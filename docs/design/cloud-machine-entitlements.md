# Cloud machine entitlements — AWS first

The first implementation is a pure AWS policy evaluator in
`internal/cloudentitlements/awspolicy`. It evaluates one action/resource permission
check against the supplied policy evidence and request context. It makes no
network or database calls. The read-only IAM collector captures selected workload users and roles through
queued discovery. Scoped activity findings feed policy models and generated
access reviews. Reviewed policy changes and key replacement are separate paths. The evaluator alone does not establish the full operator workflow.

## Evidence and decisions

Every policy category has explicit coverage: `complete`, `verified_absent` or
`unavailable`. A missing fetch is not a verified lack of a boundary or organization
policy. A context key can likewise be known absent or unobserved. Unknown evidence
cannot justify an Allow. An applicable explicit Deny wins; otherwise the result is
`allowed`, `implicit_deny` or `indeterminate` for the captured check. Reasons name
source documents and statements without echoing condition values.

Identity policies combine their grants. Boundaries and session policies limit
those grants. SCP/RCP hierarchy levels also limit the result and do not create
permissions by themselves. RCPs match their required wildcard principal; inverse
principal/action forms and custom Allow shapes remain indeterminate. The native
RCPFullAWSAccess default must be present in a complete enabled RCP capture.
[Source: AWS RCP syntax](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps_syntax.html). Same-account resource grants distinguish a user or
session principal from a role ARN or account delegation. This distinction matters:
a direct user/session grant can survive an implicit boundary denial, while an
explicit denial remains effective. A Deny with NotPrincipal also respects AWS's
special treatment of principals with attached permissions boundaries.
[Source: AWS evaluation rules](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html),
[AWS boundary rules](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html).

Conditions support string/ARN equality and wildcards, case-insensitive string
equality, negated comparisons, IfExists, ForAllValues/ForAnyValue, Null, Boolean,
IP/CIDR, ordinary finite decimal numeric comparisons and RFC3339/epoch date
comparisons. Missing-key and negated-value behavior is tested separately. Context
keys fold case; conflicting spellings are refused. Principal ARN/account context
comes from the declared validated principal and cannot be replaced by context
input. Numeric forms beyond 15 digits or extreme magnitude remain indeterminate.
Unknown operators, policy variables and unsupported principal forms stay visible.
[Source: AWS condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html).

## Input and work bounds

A policy body is at most 64KiB with 256 statements. Duplicate JSON keys, ambiguous
selectors, unknown statement fields and invalid conditions are rejected. Parsed
documents own their data; raw receipt access returns a copy. Evaluation bounds
policy sets, organization levels, total statements, context keys/values and a
shared work budget. Pattern, condition and principal comparisons consume that
budget. Explanations are also bounded. Exhaustion reports indeterminate work.

## Qualification limits

The checked-in 59-case suite is **authored from official AWS documentation**. It
is not a native AWS capture, IAM simulator differential or published AWS conformance
result. Property tests cover denial preservation, unread-policy safety, immutable
parsing and wildcard matching against a bounded independent reference. Native Go
fuzz targets cover policy JSON, wildcard matching and condition-value parsing.

The model covers the stated IAM policy check, not every mechanism that can affect
an AWS API operation. Cross-account authorization, KMS grants/key policy details,
role trust authorization, service-linked-role exceptions and federated-user session
identity are currently indeterminate. Service-specific checks, ACLs, endpoint
policies and multi-resource API requirements need explicit capture/modeling before
an entire API action can be claimed authorized. A complete CloudTrail record is
not assumed to contain a complete AWS condition context. Live AWS qualification
and the complete inventory/remediation journey remain unproven.

## Selected IAM inventory

`internal/cloudentitlements/awsiam` reads explicitly named workload users/roles,
including user group policies, inline and pinned managed-policy versions,
permissions boundaries, role trust documents and key creation/last-use metadata.
It does not infer that every account user is a machine. Each parsed policy has a source receipt and SHA-256 digest of the original
bytes. The receipt also carries those original bytes as base64 `raw_document`,
so its digest remains verifiable after JSONB reorders the readable `document`. Capture is a series of reads, not an atomic
cloud snapshot; later mutation approval must bind and recheck source evidence.

The collector borrows fresh STS response bytes from an owner-only local file for
each request. It refuses expired sessions, missing session tokens and shared
files. Secret signing headers move through locked memory directly to the socket;
they do not enter Go HTTP header strings. The fixed origin uses verified TLS and
DNS-time egress checks, with an explicit loopback-only plaintext lab option. No
redirects or automatic retries occur. The read operation allowlist contains no
credential creation, policy mutation or revocation calls. The served discovery integration executes the collector through the existing
outbox-backed bounded worker.

At most 256 selected principals, 64 policy receipts per identity, 100 pages and 2048
members per list, 5000 calls, 8MiB of source policy/trust bytes and five minutes per capture are accepted. Each call
has a 30-second limit, 64KiB headers and 4MiB response limit; XML depth/tokens,
policy bodies and local session files are bounded. A failed policy/group/key read
does not publish a partially complete identity. Organization SCP/RCP, resource
policy and activity-log coverage remain unavailable until separately captured.

`bash scripts/labs/cloud-entitlements.sh` uses only the cached pinned LocalStack
image and stock `awslocal` to seed a disposable fixture. It proves native IAM
metadata capture, approved key deletion and restrictive-policy readback, then
stops its exact container and retains its private proof directory. The served
journey also proves distinct human approval, queue rollback recovery, tenant
isolation and immutable result replay. LocalStack does not enforce IAM
permissions. Key replacement, GCP/Azure inventory, live cloud enforcement and
whole-workflow completion remain separate requirements.


## Durable assessment records

The `cloud_machine_entitlement` source validates exact field names before
credential-reference admission. Unknown credential fields, case aliases and
duplicate source fields are refused. The fixed assessment schema treats IAM
condition keys such as `aws:TokenIssueTime` as public policy metadata; it accepts
no credential-value field. Every actual credential remains in the private STS
file. A state-free preview identifies the selected principals and five-minute
capture bound without fetching credentials or making cloud calls.

Each identity assessment retains its scoped policy/activity/check inputs and a
source-input digest. Later source edits do not replace this evidence. The bounded
assessment is an immutable discovery event projected under the
source tenant's RLS context. Imported organization/resource and activity evidence
remains explicitly identified. Typed assessment fingerprints canonicalize JSON object order and exact decimal
number meaning without floating-point rounding so PostgreSQL JSONB cannot invalidate unchanged facts. The graph
also checks source kind and terminal native-run provenance before creating any
modeled permission edge; a copied manual record cannot become native evidence.
Only the latest captured principal snapshot contributes grant edges, and only
within the 24-hour freshness window. A denied check remains visible as a checked
resource without retaining an earlier modeled Allow. Generated access reviews
carry the finding/check provenance and the model's qualification limits.

Canonicalization bounds decoded depth to 64, nodes to 100000 and estimated expanded
numeric/string evidence to 1MiB; numeric exponents outside ±4096 are refused. A
published assessment event remains at most 512KiB. Graph decoding permits 2MiB for
JSONB formatting/decimal expansion and then enforces canonicalization bounds.

## Reviewed native AWS changes

A fresh native capture includes the IAM `UserId` or `RoleId`, endpoint, and source
configuration digest. Captures older than 24 hours and older captures without
these bindings cannot authorize a change. Proposals preserve this public evidence
and a reference to an operator-approved private STS writer file. They contain no
credential values. `access:write` plus `discovery:read` can propose; private
endpoints also require `egress:private`. The human approval queue requires
`access:approve`; the console reviewer also needs `access:read` to inspect the
exact intent before its approval button becomes available. A requester cannot
approve their own proposal. The default quorum is two distinct reviewers; an
explicit quorum may select one through five.

`revoke_key` deletes only the named captured IAM user key. `tighten_policy` creates
one separate `trstctl-tighten-…` inline policy with an explicit Deny for one exact
unused action and resource ARN. Complete recorded activity coverage is required.
The new Deny applies in **all contexts**; the approval review must account for
that impact. Existing grants, conditions, and denies remain untouched. A matching
existing owned policy is a replay; different content under that name is refused.

The approval digest binds the entire intent. Execution is requester-only and
consumes that exact approval in the same PostgreSQL transaction that projects
queued state and enqueues the external intent. A separate bounded outbox pool
performs the IAM operation. Startup and periodic recovery repair retained queue
and result events after database rollback. The worker checks the source digest,
execution deadline, and native principal ID, then independently reads the native
key list or policy. `verified` means that readback matched. It does not prove
live AWS enforcement or that a workload adopted replacement credentials. An
unverified native attempt reports `effect_uncertain`; operators must recapture
and review its current state before another change. There is no blind inverse
write. IAM's name-based mutation APIs do not offer an atomic principal-ID
precondition; pre/post ID checks detect replacement, but cannot make that upstream
operation transactional.

These are historical capture findings. After a verified change, run the source
again to refresh inventory and graph evidence. Key replacement, repeated workload
adoption, live AWS enforcement, and GCP/Azure mutation qualification are separate
requirements and are not implied by a successful native readback.


## STS replacement preparation

The existing `aws-sts` dynamic provider can prove a temporary lease by signing
[GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)
with that lease. Its returned account, assumed-role ARN and native role/session
ID must agree with an operator-allowed role; IAM role paths do not become STS
session paths ([AWS identity identifiers](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html)).
This read needs no IAM permission grant and does not prove resource authorization.
The separate fixed STS action/version/signing scope shares the bounded, redirect-
free byte transport; the inventory operation allowlist is still IAM read-only.
The dynamic lease JSON parser accepts only the four exact expected fields,
rejects aliases, duplicates, missing session tokens and expired/overlong lifetimes,
locks decoded fields, and wipes them after the signing callback.

Durable dynamic-lease rotation also accepts `aws-sts`: it publishes a new sealed
secret version and records an authenticated native identity check. Existing
predecessor retirement stays pending until the configured native denial mechanism
or actual native expiry. This prepares a short-lived credential; the separately
reviewed cloud replacement still has to prove workload adoption and retire the
captured long-lived IAM key.
