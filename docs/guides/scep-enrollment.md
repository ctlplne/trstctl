# Device enrollment with SCEP

The full protocol behavior lives in
**[Enrollment protocols](../features/enrollment-protocols.md)** — capabilities,
CA/RA material, CMS request handling, challenge validation, idempotency, rate
limits, and failure behavior. For the end-to-end device journey, see
[Enroll devices & IoT fleets](../journeys/enroll-devices.md).

Before connecting a router, printer, phone, laptop, or MDM profile, open
**Certificates → Enrollment methods → Set up and operate methods → SCEP
connection check**. The console previews three exact requests before it runs:

1. read the responder capabilities;
2. read and structurally validate the public CA or CA/RA material; and
3. send an empty, credential-free `PKIOperation` that must fail closed.

The check does not create or send a PKI message, CSR, challenge, credential,
certificate request, private key, or browser session. It cannot issue a
certificate. A green third row means broken input was rejected before SCEP
could read a CSR or challenge; a success response is a red security-control
failure.

If a row fails, do not weaken CMS validation or the MDM challenge requirement.
Repair the named responder, CA/RA, or signer configuration and choose **Run
again**. A real device generates and retains its private key, then sends a
CMS-wrapped CSR with an approved, short-lived MDM challenge.
