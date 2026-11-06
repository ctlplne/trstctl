# Cloud machine entitlements — A264, AWS first

The first implementation is a pure AWS policy evaluator in
`internal/cloudentitlements/awspolicy`. It evaluates one action/resource permission
check against the supplied policy evidence and request context. It makes no
network or database calls. The read-only IAM collector captures selected workload users and roles. Activity
findings, reviewed policy changes/key replacement, graph/review integration and
operator interfaces are subsequent slices. This package alone does not establish the A264 workflow.

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
and the complete A264 inventory/remediation journey remain unproven.

## Selected IAM inventory

`internal/cloudentitlements/awsiam` reads explicitly named workload users/roles,
including user group policies, inline and pinned managed-policy versions,
permissions boundaries, role trust documents and key creation/last-use metadata.
It does not infer that every account user is a machine. Each parsed policy has a
source receipt and SHA-256 digest. Capture is a series of reads, not an atomic
cloud snapshot; later mutation approval must bind and recheck source evidence.

The collector borrows fresh STS response bytes from an owner-only local file for
each request. It refuses expired sessions, missing session tokens and shared
files. Secret signing headers move through locked memory directly to the socket;
they do not enter Go HTTP header strings. The fixed origin uses verified TLS and
DNS-time egress checks, with an explicit loopback-only plaintext lab option. No
redirects or automatic retries occur. The read operation allowlist contains no
credential creation, policy mutation or revocation calls. Production integration
must execute the collector through an outbox-backed discovery worker.

At most 256 selected principals, 64 policy receipts per identity, 100 pages and 2048
members per list, 5000 calls, 8MiB of retained policies/trust and five minutes per capture are accepted. Each call
has a 30-second limit, 64KiB headers and 4MiB response limit; XML depth/tokens,
policy bodies and local session files are bounded. A failed policy/group/key read
does not publish a partially complete identity. Organization SCP/RCP, resource
policy and activity-log coverage remain unavailable until separately captured.

`bash scripts/labs/cloud-entitlements.sh` uses only the cached pinned LocalStack
image and stock `awslocal` to seed a disposable fixture. It proves native IAM
metadata capture, then stops its exact container and retains its private proof
directory. This is not native AWS permission enforcement or a served UI/API
workflow. LocalStack does not enforce IAM permissions. No live AWS account,
key replacement, GCP/Azure inventory or whole A264 completion is claimed here.
