# Device enrollment with EST (RFC 7030)

trstctl serves **EST** (Enrollment over Secure Transport, RFC 7030) so network
devices and IoT fleets — Cisco, Aruba, and the like — enroll and re-enroll for
certificates automatically, under certificate-profile control (see
[certificate profiles](profile-authoring.md)).

## Endpoints

All endpoints are served under `/.well-known/est/` over TLS:

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/cacerts` | GET | Returns the CA chain as a certs-only PKCS#7. A client fetches this first to establish explicit trust. No auth. |
| `/simpleenroll` | POST | Enroll: the body is a base64 PKCS#10 CSR; the response is the issued certificate as a certs-only PKCS#7. Authenticated. |
| `/simplereenroll` | POST | Re-enroll (renewal): same shapes as `/simpleenroll`. Authenticated. |
| `/csrattrs` | GET | Advertises required CSR attributes. This server imposes none beyond the bound profile and returns `204 No Content`. |

## How a device enrolls

1. `GET /cacerts` and install the returned CA chain as the explicit TLS trust
   anchor.
2. Generate a key and a PKCS#10 CSR.
3. `POST /simpleenroll` the base64 CSR with its enrollment credential (HTTP auth on
   top of TLS, RFC 7030 §3.2.3). On success the device receives its certificate in a
   PKCS#7 and installs it.
4. Before expiry, `POST /simplereenroll` to renew.

## Profile control and safety

Every enrollment is validated against the EST endpoint's **bound certificate
profile** before anything is signed: a request for a disallowed key type/size, EKU,
over-long validity, or a name outside the profile's constraints is rejected. Each
enrollment is an **audited event** (who/what/when), issuance is **idempotent** (a
retried enrollment never mints two certificates) and **outbox-mediated**, and an
enrollment burst is **bulkheaded** so it cannot starve unrelated subsystems — a
saturated enrollment pool sheds with `503 Service Unavailable` rather than degrading
the control plane.

## Failure behavior

A malformed request (not base64, or not a valid CSR) fails closed with
`400 Bad Request`; an unauthenticated request gets `401 Unauthorized`; a request the
bound profile rejects gets `403 Forbidden` with the reason.
