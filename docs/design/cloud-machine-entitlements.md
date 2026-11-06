# Cloud machine entitlements — A264, AWS first

The first implementation is a pure AWS policy evaluator in
`internal/cloudentitlements/awspolicy`. It evaluates one action/resource permission
check against the supplied policy evidence and request context. It makes no
network or database calls. Inventory collection, activity findings, reviewed
policy changes/key replacement, graph/review integration and operator interfaces
are subsequent slices. This package alone does not establish the A264 workflow.

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
