# Device enrollment with EST

This guide's content now lives in
**[Enrollment protocols](../features/enrollment-protocols.md)** — the EST
endpoint table (`/.well-known/est/cacerts`, `/simpleenroll`, `/simplereenroll`,
`/serverkeygen`), status-code behavior, certificate-profile control, and
failure modes, alongside SCEP and CMP. For the end-to-end walkthrough, see the
[Enroll devices & IoT fleets journey](../journeys/enroll-devices.md). This
page remains as a pointer for existing links.

Before connecting a device, open **Certificates → Enrollment methods → Set up
and operate methods → EST connection check**. The console shows the exact
three-request plan before it runs: fetch the CA chain, read the CSR rules, and
send an empty credential-free enrollment request that must fail closed with a
Bearer challenge. This check never creates or sends a CSR, token, private key,
or certificate. A failed row names the broken door; repair that configuration
without weakening authentication, then choose **Run again**.
