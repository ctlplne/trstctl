# Enroll devices and IoT fleets

<!-- trstctl:journey-census:start -->
!!! success "Served path — wiring census 81/81"

    The shipped-binary census reports **81/81 required capabilities served**.
    DoD-gated rows used by this journey (all `required`, all `served`): `pqc_end_to_end.pure_mldsa_leaf_stock_clients`, `protocol_ergonomics.eval_profile`.
    Core surfaces guarded by route and journey tests: `est_protocol`, `scep_protocol`, `cmp_protocol`, `device_bootstrap`.
    This badge is generated from `wiring-census.json`; `make journey-census-check` fails closed if the census or this page drifts.
<!-- trstctl:journey-census:end -->

## Goal

When you finish this journey, the routers, switches, printers, phones, and IoT
devices you already run will enroll for trstctl-issued certificates over the
enrollment protocols baked into their firmware — and renew before expiry — without
re-flashing a single device. It is for teams with an existing fleet of network or
embedded gear that speaks EST, SCEP, or CMP. In plain terms: a device asks trstctl
for a certificate using the protocol it already knows, trstctl checks the request
against its rules, and hands back a signed certificate.

## Before you start

- A running trstctl control plane with a provisioned issuing CA. Bring one up via
  [Getting started](../getting-started.md).
- A device (or a standard client such as a stock EST client) that speaks EST, SCEP,
  or CMP.
- For depth on the protocols, certificate-profile control, and failure behavior, see
  the [Device enrollment with EST guide](../guides/est-enrollment.md), whose concrete
  flow this journey lifts.

## Steps

1. Enable the enrollment protocol your fleet speaks. Each protocol server is off
   by default and binds to a tenant. For EST, turn it on:

   ```yaml
   protocols:
     est:
       enabled: true
       tenant_id: "11111111-1111-1111-1111-111111111111"
   ```

   You should see the control plane mount EST under `/.well-known/est/...` (and,
   similarly, SCEP at `/scep` and CMP at `/cmp` when enabled) on startup. The three
   protocols and what each industry uses are covered in
   [Enrollment protocols](../features/enrollment-protocols.md).

2. Fetch the CA chain to establish trust. A device fetches the CA chain first
   (no auth) so it can bootstrap explicit trust before sending anything:

   ```sh
   curl -s https://trstctl.example.com/.well-known/est/cacerts -o cacerts.p7
   ```

   You should receive a certs-only PKCS#7 chain. The device installs it as its
   explicit TLS trust anchor.

3. Enroll: POST a CSR, get back a certificate. The device generates its key
   locally (the private half never crosses the wire), builds a PKCS#10 CSR, and
   enrolls. With a stock client this is a base64 CSR POSTed to `/simpleenroll`:

   ```sh
   curl -s -H "Content-Type: application/pkcs10" \
        -H "Idempotency-Key: $(uuidgen)" \
        --data-binary @request.b64 \
        https://trstctl.example.com/.well-known/est/simpleenroll
   ```

   You should get back the issued certificate wrapped in a PKCS#7. Every enrollment
   is validated against the endpoint's bound certificate profile *before* anything is
   signed — a disallowed key type, EKU, over-long validity, or out-of-profile name is
   rejected. The profile model is described in
   [Issuance & certificate authorities](../features/issuance-and-cas.md).

4. Renew before expiry. Before the certificate expires, the device re-enrolls
   over the same protocol — for EST that is a `POST` to `/simplereenroll`, the same
   request and response shapes as the first enroll. You should see a fresh
   certificate issued the same way. Because issuance is idempotent, a retried
   enrollment never mints two certificates.

5. For the smallest devices, bootstrap with a one-time token. Constrained IoT
   hardware that cannot run a full agent bootstraps with a single-use token over the
   served endpoint; the device generates and keeps its own key and sends only a CSR:

   ```sh
   curl -s -X POST https://trstctl.example.com/enroll/bootstrap \
        -d '{"token":"<one-time-token>","csr":"<base64-DER-CSR>"}'
   # -> {"certificate":"<PEM chain>"}
   ```

   You should receive a PEM certificate chain. The token is checked-and-deleted
   atomically, so it works exactly once.

6. For MDM-managed phones and laptops, gate enrollment with a challenge. When a
   mobile-device-management platform (Intune, JAMF) pushes a SCEP profile, you want
   only MDM-provisioned devices to enroll. trstctl issues an HMAC-signed challenge
   token the MDM embeds in the device's SCEP profile `challengePassword`, and the
   SCEP server validates it (constant-time check, expiry) before issuing — fail-closed
   on any defect. You should see enrollment succeed only for devices carrying a valid
   challenge. This is covered in
   [Enrollment protocols](../features/enrollment-protocols.md).

   > Served boundary: EST, SCEP, CMP, embedded bootstrap, and embedded renewal are
   > cross-checked end to end. With the Enterprise/PQC license attached, the same EST
   > route accepts an RFC 9881 ML-DSA-65 CSR produced by stock OpenSSL 3.5 and returns
   > a pure ML-DSA leaf that stock OpenSSL verifies. The MDM challenge gate is also
   > served; its live validator trust anchors come from
   > `protocols.scep.intune_challenge` startup configuration, while policy CRUD and
   > rotation evidence remain visible through `/api/v1/mdm/scep/*`.

## Where next

- [Automate TLS across your fleet with ACME](automate-fleet-tls.md)
- [Give your Kubernetes workloads an identity](kubernetes-workload-identity.md)

**Journey:** J4
**Steps through:** F22, F23, F55, F54, F56
