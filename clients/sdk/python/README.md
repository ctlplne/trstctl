# trstctl Python SDK

`trstctl-sdk` is the official Python client for the served trstctl REST API. It
is generated and tested against `clients/sdk/openapi.json`, the pinned copy of
the OpenAPI document served by the control plane.

The runtime uses only the Python standard library and provides the same client
contract as the Go and TypeScript SDKs:

- `Authorization: Bearer <token>` on every call, plus optional `X-Tenant-ID`;
- `Idempotency-Key` on every mutation, auto-generated when not supplied and held
  stable across automatic retries;
- RFC 7807 `application/problem+json` responses as `ProblemError`;
- bounded retries for `429`, `502`, `503`, and `504`, honoring `Retry-After`;
- OpenAPI-derived `TypedDict` aliases in `trstctl_sdk.types`.

```python
from trstctl_sdk import ProblemError, TrstctlClient

client = TrstctlClient.from_env()

try:
    issued = client.issue_pki_secret(
        "payments.service",
        ttl_seconds=900,
        idempotency_key="payments-pki-2026-06-25",
    )
    client.create_secret(
        "apps/payments/api-token",
        "initial-fixture-value",
        idempotency_key="payments-secret-create",
    )
    current = client.get_secret("apps/payments/api-token")
except ProblemError as exc:
    print(exc.http_status, exc.title, exc.detail)
    raise

print(issued["serial"], current["version"])
```

Environment variables used by `TrstctlClient.from_env()`:

```bash
export TRSTCTL_SERVER=https://localhost:8443
export TRSTCTL_TOKEN=trst_...
export TRSTCTL_TENANT=11111111-1111-1111-1111-111111111111
```

Regenerate the OpenAPI type aliases from the repo root:

```bash
make sdk
make sdk-check
make sdk-test
```
