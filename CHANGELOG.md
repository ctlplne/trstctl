## [Unreleased]

### Added
- Billing systems for the Provider plane (MSP-2, part 1): `provider.billing_sync.targets` names the billing or PSA
  systems a Provider pushes customers' signed usage periods to (signed JSON targets with an HMAC `signing_key_ref`,
  an optional bearer `token_ref`, monthly or daily cadence), and a Provider operator with the new `billing:write`
  permission maps each delegated customer to its company in each target
  (`PUT`/`DELETE /provider/v1/tenants/{id}/billing-companies/{target}`, `GET .../billing-companies`). Mappings are
  Provider authority events projected into `provider_billing_companies`; one company in one target belongs to one
  customer (409 before anything is recorded). The Provider console's Billing section shows and edits them. The
  period pushes themselves arrive with part 2.
- 1Password Connect and Doppler as `cloud_secret` and `secret_store` discovery providers (OD-14, restored from A173):
  `1password-connect` lists the items of a Connect server's vaults (titles and categories; field values only with
  `inspect_content`), and `doppler` lists secret names per project config from the names-only endpoint (values only
  with `inspect_content`). Both are proven against stand-ins written from their public API references; the source
  wizard, the source catalog (twelve secret-store providers) and the Secrets page include them.
- Four more secret stores for `cloud_secret` and `secret_store` discovery (OD-13): `infisical` (Universal Auth or an
  access token; projects, environments and folders), `conjur` (a host's or user's API key; variables under a policy
  path), `akeyless` (an API-key access ID; static secrets under a folder) and `bitwarden-secrets-manager` (a machine
  account's access token, whose key decrypts names on the client through the new `internal/crypto/bwsm`). Each lists
  metadata without reading a value, and with `inspect_content` finds certificates and API keys while keeping no value.
  Infisical and Conjur are proven against their official images pinned by digest; Akeyless and Bitwarden Secrets
  Manager against stand-ins. The source wizard asks for each one's sign-in, the source catalog lists ten secret-store
  providers, and the Secrets page shows the four beside the cloud managers (it now counts `secret_store` sources too).
- A signed generic CI secret push (OD-12): a `generic-ci-json` sync target that names a `signing_key_ref` signs every
  push like the signed webhook (`X-Trstctl-Timestamp`, `X-Trstctl-Signature` = HMAC-SHA256 over the timestamp and the
  exact body, `X-Trstctl-Delivery`), so the receiver can refuse a changed or replayed push with
  `secretsync.VerifyWebhookSignature`; the envelope and the bearer token are unchanged, and a target without a key
  stays the bearer-only push. The target catalog and the console's target table mark a signed target
  `signed-payload`.
- An audit retention floor for offboarded tenants' event keys (OD-11): `privacy.event_protection.audit_retention_floor`
  (`TRSTCTL_PRIVACY_EVENT_PROTECTION_AUDIT_RETENTION_FLOOR`, a year by default, `0s` off, at most ten years) keeps an
  offboarded tenant's key, and so its audit archives, event history and backups readable, at least that long after the
  offboard even when the tenant chose a shorter retention window. Waiting for it spends none of the destruction's retry
  budget, and the hold clearance written before the removal records `retention_floor_until` and
  `retention_floor_seconds` when the floor kept the key. A legal hold still wins; a hold refusal at removal time now
  also waits without spending the retry budget instead of exhausting it.
- Tenant and deployment KEKs under a cloud KMS key (OD-10): a `kms` wrapper kind the isolated signer keeps as an
  AES-256 wrapper key that an AWS KMS, Google Cloud KMS or Azure Key Vault key wraps through the KMS wrap adapter
  (`kms_wrappers` and `kms_wrap_command` in the signer's tenant KEK file; the wrapped key file is created on first
  start; `secrets.tenant_seal_kms_wrappers` / `TRSTCTL_TENANT_SEAL_KMS_WRAPPER_ID` on the control plane). Tenants
  migrate and rotate onto it, and the deployment KEK rotates onto it, from the console or `wrapper_kind: kms`; the
  status reports `signer_kms`. The signer reaches the KMS for every use unless the operator sets `kms_cache_seconds`
  (off by default, at most a day): the unwrapped key then stays in locked, non-dumpable memory until the limit, when
  it is wiped, and shutdown wipes it at once. A KMS that does not unwrap fails the tenant closed as
  `wrapper_unavailable`.
- Standing approvals for an access bundle's delegated accounts (OD-9): never on by default; an administrator with
  `access:approve` as well as `access:write`, who the bundle is not granted to, grants one for one delegated account
  and role with a reason and an expiry at most 90 days away (`POST /api/v1/access/bundles/{id}/standing-approvals`,
  `trstctl-cli access bundles standing-approvals grant`, or Standing approvals on the Agent access page). The bundle's
  runs' session requests for that account and role are then approved without a reviewer while the run's grant is
  live, the bundle still delegates them and the session ends before the approval expires; the request records one
  approval by `standing-approval:<id>`. Sessions stay recorded and revocable; revoking the approval (with a reason)
  ends the live sessions it approved, refuses one it approved that was not opened yet, and the next request waits for
  reviewers. The bundle's activity records each grant, each approved session's run and the revocation. Migration 0463.
- Standing approval for a SPIRE server's upstream CA requests (OD-8): two custodians approve one
  `grant_upstream_standing_approval` ceremony naming the SPIRE server's token subject, its trust domain, the CA spec
  (its `ttl_seconds` the longest CA lifetime) and how long the approval lasts (at most 90 days), and an administrator
  grants it (`POST /api/v1/ca/authorities/{id}/upstream-standing-approvals`, `trstctl-cli ca authorities
  standing-approvals grant`, or Standing approvals in the authority's details). Until it expires or is revoked, the
  SPIRE upstream authority plugin's CA CSRs are signed without a ceremony each when they name exactly
  `spiffe://<trust domain>` within the approved spec and lifetime; anything else is refused. Each such CA carries a URI
  name constraint for the trust domain, every signing is audited (`ca.upstream_standing_approval.signed`) and counted,
  and revoking it (with a reason) makes the next CA need a ceremony again. Migration 0462 adds the approvals table.
- Venafi revocation by certificate DN (OD-7): a `venafi` external CA with `revoke_by: certificate_dn` revokes by the DN
  of the certificate object whose current certificate has the certificate's thumbprint (found with Venafi's certificate
  search), for a policy that revokes only by DN; an object that has moved on to another certificate, or a thumbprint
  more than one object holds, is refused rather than revoked. The external CA list and the console's issuer
  revocation picker name it.
- An RS256 key option for the OpenID issuer (OD-6): `protocols.spiffe.jwt_key_algorithm: RS256`
  (`TRSTCTL_PROTOCOLS_SPIFFE_JWT_KEY_ALGORITHM`) has the signer create the workload JWT keys as RSA-2048, so a cloud
  that accepts only RS256 trusts exchanged workload tokens; the issuer advertises RS256 and publishes an RSA key, and
  a rotation's next key is RSA too. The default stays ES256; a key already in the signer keeps its algorithm until a
  rotation replaces it, and the console's issuer panel says how to get RS256 while none is published.
- A GitHub App or OAuth lease's completed revocation names how its token ended (OD-5), as an AWS STS lease's does:
  `revocation_method` is `token_revoked` when the provider confirmed the presented token ended (GitHub's
  `DELETE /installation/token`, an RFC 7009 revocation endpoint) and `native_expiry` when it lapsed at its own expiry
  (OAuth without a revocation endpoint). Leases add `native_expiry_kind` (`aws_session`, `oauth_token`,
  `github_app_token`), and the console's lease view names the token or session that way instead of calling every
  expiring credential an AWS session. Migration 0461 admits the new method.
- Leaked-secret scans read Microsoft Teams channel messages and Confluence content (OD-4): third-party scan providers
  `teams` (a team's channels and their replies from Microsoft Graph, Graph's next pages followed on its own origin only,
  posters' addresses for owner linking) and `confluence` (the pages, blog posts and comments a CQL query selects, the
  site's own next links followed), for an export's `artifact_path` or a native `collect` (`team` and `channels`, or
  `cql`). Findings name the Teams message (team, channel, message, reply, poster) or the Confluence content (ID, type,
  space), never the content. The console's third-party scan form offers both.
- Native GitLab and Bitbucket push hooks for repository secret scans (OD-3): `secrets.scan_webhooks` takes
  `provider: gitlab` (the hook's signing token checks `webhook-signature` over `webhook-id`, `webhook-timestamp` and the
  body, refusing a stale timestamp; a hook with a secret token checks `X-Gitlab-Token`) and `provider: bitbucket`
  (`X-Hub-Signature`, HMAC-SHA256 of the body; Cloud `repo:push` and Data Center `repo:refs_changed`). A verified push
  scans each pushed branch or tag, a refused delivery is audited, and the provider's delivery ID keeps redeliveries
  idempotent.
- GitHub Dependabot and Codespaces secrets and GitLab instance variables (OD-2): a `secret_store` source's
  `github-actions` provider lists the repository's and organization's secrets in each chosen store (`stores`:
  `actions`, the default, `dependabot`, `codespaces`) and, with `user_codespaces`, the token owner's own Codespaces
  secrets; each finding names its store and scope, metadata only. The `gitlab-ci` provider's `instance: true` lists
  the instance-level variables every project inherits with an administrator's token, wiping each value unless content
  inspection is chosen. An unknown store, or a token GitLab refuses for instance variables, fails that provider with
  the reason. The console's source setup offers the stores, the owner's Codespaces secrets and instance variables.
- Repository secret scans clone private repositories (OD-1): the normalized repository webhook's `credential_ref`
  (`file:` or `secret://`, with `credential_username`) and a native GitHub hook's `clone_credential_ref` give the token
  an https clone authenticates with. The scan worker opens it for that clone alone and hands it to git as an
  Authorization header for the clone URL's origin only, through git's environment, never its arguments, the URL or the
  checkout; a redirect elsewhere gets nothing, and a refused token fails the run without echoing the host's answer.
- A planned CA switch can move to a vendor CA (P3-L2): `new_external_ca_id` (an available CA from the external CA
  registry) with `new_trust_anchor_pem` (its root), or **Vendor CAs** in the Migration page's issuer choice. Host
  members trust the vendor root first, then the vendor signs the certificate request each host makes, and the endpoint
  is verified serving the vendor's chain before the predecessor is revoked.
- A planned CA switch can move away from a vendor CA (P3-L2): a member whose current certificate the external CA
  registry issued is admitted when that vendor's integration can revoke, and once its successor is verified live the
  predecessor is revoked (superseded) at the vendor; the revocation is recorded, and the member done, only when the
  vendor accepts it (a request held for an approver is sent again; a vendor that cannot revoke pauses the run). The
  assessment names the revoking vendor (`external_ca_id`), and the cohort planner selects by external issuer too.
- Every replaced endpoint waits for wire evidence (X3-L1): when a verification finds an endpoint serving another
  certificate than before — a plain renewal's deployment or any other replacement — the endpoint records the replaced
  certificate and waits, without a migration run, until an observer agent sees new connections at it (presenting the
  replacement on TLS 1.2). That evidence is kept on the endpoint (`traffic`: awaiting, observed or unobserved, in
  `GET /api/v1/endpoints/verifications` and on the Connectors page) and closes the observer's findings for the replaced
  certificate there; nothing closes on the probe alone.
- Kubernetes token decoys (Q6-O2): `POST /api/v1/secrets/honeytokens/kubernetes` (`trstctl-cli secrets honeytokens
  kubernetes register`, and the console's decoy credentials) registers a service account bound to nothing and returns
  the manifest that plants it with its token Secret, and the audit rules its cluster needs; trstctl never holds the token.
  The cluster's API server sends its audit events to `/api/v1/secrets/honeytokens/kubernetes/clusters/<cluster>/audit-events` with a token
  holding only the new `decoys:events.report` permission. A read of the Secret alerts naming the principal, and any
  request made with the token alerts naming the client; each reader alerts once.
- Host agents plant decoy files (Q6-O1): `trstctl-agent --decoy-ssh-keys PATH[,PATH...]` (Linux, host role) writes a
  decoy SSH private key, generated on the host and authorized nowhere, at each path where no file is, registers it over
  the agent channel by its public half (`ReportDecoys`), and watches it; each program that opens it raises one critical
  decoy alert naming the program and the host. fanotify (with `CAP_SYS_ADMIN`) names every opener; inotify names one
  that still holds the file. The agent's own scans skip its decoys. The registry lists them
  (`GET /api/v1/secrets/honeytokens/files`, `trstctl-cli secrets honeytokens files list`, and the console's decoy
  credentials) with the first opener and how many programs opened each, and `retire` stops alerting.
- The passive network observer reads QUIC and DTLS over UDP (X1-L4 part 2): it removes the published protection of
  QUIC Initial packets (RFC 9001; versions 1 and 2) to read the ClientHello and ServerHello, however many packets they
  span, and reads DTLS hello messages, certificates and ECDHE groups in the clear through a cookie exchange. Findings
  are `tls_handshake` with `protocol` `quic` or `dtls`; HTTP/3 on port 443 is watched by default. Proven on real
  captures of nginx 1.30 HTTP/3 negotiating X25519MLKEM768 with OpenSSL 3.5's QUIC client, and of OpenSSL DTLS 1.2.
- Stock cosign checks a trstctl signature's transparency-log entry instead of skipping it (P9-L2): trstctl records the
  Rekor receipt it verified for each signature (`codesign.transparency_recorded`), the sign response names its
  `operation_id`, and `GET /api/v1/code-signing/identities/{operation_id}/rekor-bundle` (`trstctl-cli code-signing
  rekor-bundle`) serves the bundle `cosign attach signature --rekor-response` takes, so `cosign verify --offline`
  verifies the log's signed entry timestamp against the log's key, no `--insecure-ignore-tlog`.
- The CycloneDX CBOM export carries more than the CBOM inventory (Q3-L2): the certificates the certificate inventory
  holds for its certificate keys (subject, issuer, validity, linked to the key's component), the keys host agents found
  in keystores and key files (as private-key or secret-key material with size and format, never key bytes), the crypto
  libraries they identified (with whether each can negotiate X25519MLKEM768), and the TLS and SSH handshakes observers
  saw (version, cipher suite, key exchange group). Agent classes take the newest finding of each location, at most
  10,000 each, and the coverage metadata counts every class. The official CycloneDX 1.6 schema validates the result.
- The host agent reads Bouncy Castle FIPS keystores (BCFKS, X2-L2 part 2): the store's integrity MAC checks the password,
  the store is decrypted (PBKDF2, AES-CCM) only to reach its certificates, and its key entries, trusted certificates and
  secret keys are reported like a JCEKS store's; private and secret keys stay sealed, and a store no password opens is
  reported locked. Directory walks read `.bcfks` files.
- The host agent reads JCEKS keystores (X2-L2, part 1): key entries are reported like a JKS store's (alias, type, size,
  fingerprint, chain; certificates are in the clear, keys never decrypted), and secret key entries are stepped over
  sealed and counted; a store of secret keys only, such as a Hadoop credential store, is reported once as the keystore.
  Directory walks read `.jceks` files. Before, a JCEKS store was refused.
- A CBOM import retires what a newer BOM of its source no longer lists (X6-L3): once the BOM is in, the source's
  earlier rows that it does not list are marked inactive (`cbom.import.reconciled`; rows and events kept), named in the
  response's `retired_asset_ids` and counted on the Posture page. Another source is never touched, even one whose name
  extends it (`vendor:acme:fw` for `vendor:acme`). An earlier revision of a BOM the source already imported (same
  serial number, lower version) is refused with 409 instead of rolling the inventory back.
- The host agent reports every key of a PKCS#12 keystore (X2-L1): a Java PKCS12 keystore with several aliases, as
  keytool writes it, lists each key at `<file>#<alias>` with its type, size and chain, and counts the trusted entries;
  before, only one key of such a file was reported, without its alias and with every certificate as its chain. Keys are
  still never decrypted.
- A code-signing key's certificate chain is attached or rotated through the API (P9-L1):
  `PUT /api/v1/code-signing/keys/{key_id}/certificate` (`trstctl-cli code-signing keys attach-certificate`, or the Code
  signing page's Key certificates panel) checks the chain against the key and the `codeSigning` usage, records it, and
  stock signing tools get it from the next request on, on every replica, with no configuration change or restart.
- An access review's revoke decision acts on certificates and identities (Q1-L1): a certificate is revoked by the
  trstctl CA that issued it (`cessationOfOperation`) and an identity moves to `revoked` through its lifecycle, both as
  the reviewer through the same gate an operator's request meets. A reviewer the gate refuses (authority, policy, dual
  control) revokes nothing: the item is left `manual`, naming why.
- The host agent rates more TLS libraries for X25519MLKEM768 (X2-L4): LibreSSL by its release notes (4.3.0 and
  later), GnuTLS by whether the build names the hybrid group, NSS by the groups its `libnss3` names, and an OpenSSL
  before 3.5 whose configuration activates oqsprovider (`yes` when its default Groups list names an ML-KEM hybrid).
- A CBOM import reads the BOM's dependency graph (X6-L5): what a library component `provides` is listed under that
  library (`openssl 1.1.1w`), so a weak algorithm points at the library to upgrade, and a key or certificate takes the
  algorithm, and a certificate the issuer, that its `dependsOn` names when its own properties leave them out.
- The passive network observer reads TLS reached inside another protocol (X1-L4): SMTP and IMAP STARTTLS, POP3
  STLS, LDAP StartTLS, PostgreSQL's SSLRequest and MySQL's SSL request, each reported with its `upgrade`; a PostgreSQL
  startup, a MySQL login or a mail login sent without TLS is a `plaintext_protocol` finding. Ports 25, 587, 143 and
  110 join the observed defaults. Proven on real captures of PostgreSQL 17, MariaDB 11.8, OpenLDAP 2.6 and the mail
  protocols.
- The passive network observer reads a handshake whose segments arrive out of order (X1-L3): segments ahead of a gap
  are held (16 a direction, inside the 16 KiB it reads) and read once the gap fills, counted as `reordered`; before,
  any gap ended reading of that connection. `trstctl-agent --observe-pcap <file>` reads a saved classic pcap capture
  once and reports its handshakes like an interface's.
- `cbom scan-source` follows key sizes and curves through names (X6-L2): Go package constants and constant
  expressions, variables assigned once (across the package's files or in the function), a curve held in a variable,
  and one level of wrapper function in the same package, reported at the caller's line; Java and Python key sizes
  given as a name resolve to the number the file assigns it once. A 1024-bit key behind a constant is now found weak.
- An imported CBOM's certificates that name their SHA-256 fingerprint enter the certificate inventory (X6-L6): a
  CycloneDX 1.6 component's `hashes` or a 1.7 certificate's `fingerprint`, with the subject, issuer, serial, key
  algorithm and validity the BOM states, under source `cbom:<source>`. Expiry queries and reports now see a vendor's
  certificates; a fingerprint the inventory already holds is left as it is. The import's response lists them as
  `certificate_ids`, and the Posture page's import says how many.
- A PQC pilot can require observed traffic (X3-L5). With `require_observed_traffic`, each wave whose probe
  negotiated waits until an observer agent has seen real clients connect at every target, and keeps what they
  negotiated (TLS version, group, whether it is a post-quantum hybrid); only then does the next wave start. A target
  nobody uses within `observed_traffic_window_seconds` (default one hour) halts the pilot, and the signed readiness
  report says so. The Posture page's pilot form offers the gate, and each wave shows what real clients negotiated.
- The PKCS#11 managed-key provider generates EC P-256 and P-384 keys in the HSM as well as RSA-2048 (P9-L3): sign-only
  and never extractable, signing with `CKM_ECDSA`, the signature stored and verified in its ASN.1 form. Proven in
  SoftHSM, including an EC code-signing managed key whose certificate request is signed inside the token.
- CI templates import a repository's CBOM on every pipeline run (X6-L7, `deploy/ci`): a reusable GitHub Actions
  workflow and a GitLab CI job install `trstctl-cli` from a published release (checksums and source commit checked),
  run `cbom scan-source` and `cbom import` as `source:<repository>`, with a token that carries only `discovery:write`.
- The host agent reads the system crypto policy (X2-L6): `/etc/crypto-policies/config` and its OpenSSL back-end
  become a `crypto_library` finding (library `crypto-policies`) that says whether the policy keeps the ML-KEM hybrid
  groups in OpenSSL's TLS defaults; a LEGACY policy rates as the highest risk.
- The passive network observer reads TLS, SSH and plaintext handshakes behind VLAN tags (X1-L2): its kernel filter now
  follows up to two in-band tags (802.1Q, and QinQ with an 802.1ad outer tag) to the TCP ports, so a trunk's mirror
  port is observed; before, a QinQ frame's inner tag made the kernel drop it.
- SIEM content packs ship for the syslog and Elasticsearch audit feeds (P5-L5): the Elasticsearch/OpenSearch index
  template and ingest pipeline, and an rsyslog receiver configuration that keeps trstctl's audit messages and parses
  each record's JSON. `make siem-content` builds both into deterministic archives (`tools/siempack`); see
  `docs/guides/siem-content.md`. Proven against rsyslog 8.2608.0 and OpenSearch 3.9.0.
- An Elasticsearch/OpenSearch index template and ingest pipeline ship for the elastic audit feed (P5-L6,
  `deploy/elastic`). The template maps every field the feed writes and keeps each event type's own data unindexed,
  so event types cannot conflict over a field; the pipeline maps each batch's chain trailer as its own
  `trstctl_trailer` fields, so a chain head is one term query away. Proven against OpenSearch 3.9.0.
- A syslog audit feed can present a client certificate to a receiver that requires RFC 5425 mutual TLS (P5-L2).
  `client_cert_ref` names an operator-approved `env:` reference holding the certificate chain and key; the Audit
  page's feed form offers it for syslog. Every syslog dial now waits for a TLS 1.3 receiver's verdict on the client,
  so a receiver that refuses it fails the batch, which retries, instead of the batch counting as delivered.
- An Elasticsearch audit feed can authenticate with basic auth or a bearer token as well as an API key (P5-L4).
  `auth_scheme` (`api_key`, the default; `basic`, where the credential reference holds `user:password`; or
  `bearer`) sets the `Authorization` header; only an `elastic` feed takes one. The Audit page's feed form offers
  the choice for Elasticsearch, and the review shows it.
- A read-only planner builds canary-first migration cohorts from a selector (P3-L1). `GET
  /api/v1/migrations/cohort-plan` (CLI `migrations plan-cohorts`) places the deployed X.509 identities of a profile,
  an issuing trstctl CA, an owner or a connector in a canary and then cohorts, each member with its target's host
  agent, and lists the ones a run could not take with the reason. The Migration page's waves step plans them by
  profile or issuer and fills the waves for review. It records nothing.
- Assessing a planned CA switch lists the certificates it would revoke (P3-L4). `POST /api/v1/migrations/assess`
  with `revoke_predecessors` names each member's current certificate (id, serial, fingerprint) and the trstctl CA
  that would revoke it, by the start's own rules; a certificate no trstctl CA can revoke is a
  `predecessor_not_revocable` unknown that blocks the start. The Migration page shows the list in its review.
- An ACME authority's `upstream_dns_persist_issuer` pins which of the issuer domain names a public CA lists the
  dns-persist-01 standing record names (P1-L5). Only a record naming the pin then counts as standing, a new
  record names it, and a pin the authority does not list refuses the order before anything is published.
  Without it the record names the first listed name, as before.
- A dns-persist-01 standing record with `policy=wildcard` also validates every subdomain of its domain (P1-L2,
  draft-ietf-acme-dns-persist §5.1 and §6). The ACME server reads the name's own `_validation-persist` record,
  then its parent domains nearest first up to the registrable domain (at most 16 lookups), so one record at
  `example.com` covers `www.example.com`, `a.b.example.com` and `*.api.example.com`. A record without
  `policy=wildcard` still covers its own name only. The upstream client still publishes a record at each name.
- A Certificate Transparency finding at a precertificate entry can be revoked at an ACME CA (N10-L1). trstctl
  finds the issued certificate another watched log recorded under the same issuer and serial, reads it back from
  that log through its CT source's egress settings, checks it against that finding, and revokes it. Until a watched
  log has recorded the issued certificate, the revocation waits and says why.
- Every device of a renewal wave can check in with its MDM under one approval (N9-L2). A wave names 1 to 200 devices
  trstctl has read from that MDM. A reviewer approves exactly that set, and running it queues one check-in and one
  relay job per device, each recorded from the MDM's answer. `GET /api/v1/mdm/{mdm}/check-in-waves` counts how many
  checked in, failed or wait. The Protocols page picks the devices, or those whose renewal is at risk, asks, and
  runs the approved wave.
- An MDM device check-in the MDM throttles or fails on its side is asked again under the same approval (N9-L3).
  On a 429 or 5xx the relay posts again in the same job with the same token, at most four times, waiting for the
  MDM's `Retry-After` (at most 30 seconds) or 2, 4 and 8 seconds, and no more than a minute in all. Any other
  refusal still fails the check-in at once.
- The requests an AD CS CA holds for a manager's approval are listed from the relay's read of its database
  (N1-L2). The relay's `adcs.ca_database` read now returns, with the counts, the newest 500 pending requests
  with their request id, template, requested name and requester. Issued, revoked and failed rows still leave
  the relay as counts only. `GET /api/v1/external-cas/{id}/adcs-requests` (CLI `external-cas adcs-requests`)
  lists them per issuer, marks the ones a trstctl issuance waits on, and the CA Hierarchy page shows them, so
  an operator picks the request to decide instead of reading its id from the CA.
- Denying an approval from Slack asks for the reason (N8-L2). The Deny button opens a Slack dialog and decides
  nothing; submitting it denies the request with the reason the member typed (3 to 500 characters), recorded with
  the decision and shown in the updated message as plain text. A blank reason keeps the dialog open with the
  error on the field, and Socket Mode answers the dialog in its acknowledgement.
- An AD CS issuance held for approval finishes on its own once the issuer's relay approves its request (N1-L1).
  Recording the relay's approval queues the issuance's resume in the same transaction, and the resume reads the
  request back by its CA request id. The CA Hierarchy page lists each AD CS authority's held issuances with their
  request ids, names and outcome, and Resume finishes one a manager approved at the CA.
- An issuance an AD CS template holds for CA manager approval can be resumed by the CA's request id
  (N1-L1). When an issuance gives up waiting with the request still held, trstctl records the request id;
  `GET /api/v1/external-cas/{id}/held-issues` lists held, issued and denied issuances, and `POST
  /api/v1/external-cas/{id}/held-issues/{request_id}/resume` reads the request back once a manager approved
  it and records the certificate under the issuance's own key, so its caller gets it by replaying the request.
  The CA is never sent the request a second time. A request still held answers 409, and a denied one
  resumes as `denied`. CLI: `external-cas held-issues` and `external-cas held-issues resume`.
- Certificate Transparency monitoring watches IP addresses and CIDR ranges as well as domains
  (N10-L2). A watched `203.0.113.0/24` or `198.51.100.7` catches a logged certificate issued for
  an address in it, matched on the certificate's IP address names, which a domain watchlist never
  saw. A range that matches every address is refused. The finding names the address, keeps the
  certificate's `ip_addresses` and the entry it matched, and the plan preview names each entry
  `domain:`, `ip:` or `range:`. The console's watchlist field says what it accepts, and a
  finding's detail lists its IP addresses with its names and the entry it matched.
- Cloud access-key discovery reads Microsoft Entra app-registration client secrets (M3-L2). A
  `cloud_access_key` source's `azure-entra` provider lists every application's client secrets with
  their creation and expiry, never a value or hint, and reads each secret's last sign-in from
  Microsoft Graph's app credential sign-in activity; an active secret that has not signed in for 90
  days is flagged stale. Without that activity the secrets are recorded with their last use unknown
  and the run is partial.
- Cloud access-key discovery reads Google Cloud service-account keys (M3-L1). A `cloud_access_key`
  source's `gcp-iam` provider lists a project's user-managed service-account keys with their status,
  creation and expiry, and reads each key's last authentication from Policy Analyzer; an active key
  that has not authenticated for 90 days is flagged stale, as for AWS. When Policy Analyzer cannot be
  read, the keys are still recorded with their last use unknown and the run is partial; none is called
  stale for want of it.
- The Risk page's stale credentials show their recorded usage (M1-L3). Each stale finding for an API
  token or machine login method carries `usage`: when tracking began, its last use and where from,
  and each source it was used from, newest first, with the days seen and whether it is still new.
  The stale table's Usage column says "Last used … from …", lists the sources with the new one
  marked, or says "No recorded use since …".
- The control plane can sit behind a load balancer and still see its clients (M1-L1).
  `server.trusted_proxies` (`TRSTCTL_SERVER_TRUSTED_PROXIES`) names the proxies' networks; from a
  peer inside one, the client is the right-most `X-Forwarded-For` address that is not itself a
  trusted proxy, and from any other peer the header is ignored. API-token usage networks, EST's and
  ACME's per-client limits and OIDC sign-in limits all count that client, so a new client network
  is noticed behind a balancer instead of every request showing the balancer. A prefix matching
  every address is refused.
- The Kubernetes operator covers what the Helm chart did alone (HELM-O1). It creates the signer's
  authorization secret, and with `spec.signer.generateKek` the deployment KEK, at their default names
  when missing, with 32 random bytes; both are kept when the control plane is deleted and never
  rewritten. A multi-replica control plane gets a PodDisruptionBudget (`spec.podDisruptionBudget`,
  minAvailable 1 by default; a budget that would block every drain is refused).
  `spec.serviceMonitor.enabled` renders a Prometheus Operator ServiceMonitor scraping `/metrics` over
  HTTPS, or says the cluster lacks its API. `spec.externalKMS` runs the signer through the KMS adapter
  (`--kms-provider`, `--kms-key-ref`, `--kms-wrap-command`, `--kms-timeout`, the adapter's
  configuration Secret) instead of the KEK, in both signer topologies; an unusable KMS spec is refused.
- The Graph page says what a dynamic-secret lease reaches (G2-L4). A lease's node detail names its
  login and the target it reaches and lists each grant the target reported, with when it was read.
  A target that could not be read says why (for example, the login no longer exists) and that this
  does not mean the lease reaches nothing; a provider that cannot report and a lease not read yet
  each say so.
- The access graph shows what Kubernetes, GCP and Azure leases reach (G2-L2, part 2). A Kubernetes
  lease links to its namespace with the rules of each role a RoleBinding or ClusterRoleBinding grants
  its service account; a GCP lease links to its service account with the roles the project's IAM
  policy grants it, read from Resource Manager at `iam_endpoint`; an Azure lease links to its
  application with its app roles, directory roles and groups from Microsoft Graph. A deleted
  service account, key or client secret reads as `unknown` (`login_missing`).
- The access graph shows what MySQL, MongoDB and Redis leases reach (G2-L2, part 1). The leader
  reads each lease's login from the server itself, as it does for PostgreSQL: a MySQL lease links to
  its database with the grants `SHOW GRANTS` reports for the lease's user, a MongoDB lease with the
  user's roles from `usersInfo`, and a Redis lease to its server with the user's ACL flags, commands,
  key patterns and channels from `ACL GETUSER` (never the password hashes Redis returns beside
  them). A login the server no longer has reads as `unknown` (`login_missing`), never as no grants.
- Enrolled host agents and their roles are in the access graph (G1-L3). Each agent is a workload
  node (`agent:<agent id>`, `workload_kind: host_agent`) that `HAS_ROLE` each agent role its
  certificate carries (`agent-role:<role>`), so which machines may run network probes or hold
  sessions is a graph query, for example
  `MATCH (a:workload)-[:HAS_ROLE]->(r:role) WHERE r.name = "network" RETURN a.name`. A role grant
  the next renewal has not signed yet shows on the node as `pending_roles`, and an offboarded agent
  holds no role. Like the rest of the access side, agents need `access:read` as well as
  `graph:read`. In the console, a host agent's graph node says which roles it holds and links to
  the agent, and the Agents page opens the agent a link names.
- A certificate known only from a cloud listing can have its revocation checked (B13-L1). With
  `agent_channel.probe_scanned_certificates` on, a `cloud_certificate` run keeps the certificate the
  provider returned, only when it hashes to the certificate listed, and up to four issuers returned
  after it. AWS ACM's listing now reads the chain ACM returns with each certificate. Revocation health
  then checks that certificate's own serial at its CRL distribution points and OCSP responders,
  verified against the returned issuer or a known one that signed it, as it does for a network
  sweep's. A row an earlier listing recorded without bytes gets them from the next run.
- An operator can run the weak-key audit now (AUD-O1) instead of waiting for its six-hourly
  sweep. Use **Run the weak-key audit now** on the Discovery page's run history,
  `trstctl-cli discovery weak-key-audit run`, or `POST /api/v1/discovery/weak-key-audit/runs`
  (`discovery:write`). The request queues one discovery run under the operator's name on the
  audit's own source. The control plane runs it within the audit's bound and records the
  keys that share a prime as findings on that run. A request while an audit is queued or
  running answers with that run.
- A SAML sign-in can prove a fresh sign-in for a high-risk template (A277-O1, enterprise sign-in
  edition). Its sign-in time is the assertion's `AuthnInstant`, so a sign-in that reused an IdP
  session two hours old counts as two hours old. A fresh sign-in (`/auth/saml/login?reauth=1`)
  sends `ForceAuthn="true"` and is refused, with no session minted, when the IdP answers from
  an earlier authentication. The login page's fresh sign-in mode offers SAML, and `GET /auth/me`
  returns the session's `signed_in_at`.
- A web console that signs its users in only through an identity provider can be reached through the
  gateway (A273-O1). Its target's route names the provider (`sign_in_url`, with an optional
  `sign_in_ca_pem` and `sign_in_server_name`), and a template's `sso` web sign-in names the console
  page that starts the sign-in and the provider's form fields. The gateway follows the console's
  sign-in to that provider and no other origin, fills the provider's form with the vaulted account,
  and follows the answer back to the console. The browser never reaches the provider, and the
  provider's cookies stay at the gateway. A console that ends its session is signed in again on the
  provider's session, without the password. The console's template editor and target form take the
  mode and the provider.
- A web console's account can rotate after each session (A273-O4). A `webconsole` target may name an
  in-place account provider (ESXi, vCenter single sign-on, Redfish or a network device) that rotates
  its account secret. Once a session to it ends, the expiry worker queues one rotation through that
  provider and records it on the session, so the password the gateway signed in with no longer works.
  A rotation that cannot be queued raises one critical `pam.session.account_rotation_blocked` alert
  and is queued once it can be. The console's target form takes the optional rotation provider.
- A web console target may name the path its console lives under (A273-O3), such as
  `https://apps.internal.example/grafana/`. The browser's tunnel leads there and reaches only
  that path. Another path on the console's host is refused at the gateway and recorded,
  including one that climbs out through a dot segment, an encoded slash or a backslash. The
  template's sign-in page must lie under the path, and a session requested through a template
  that signs in elsewhere is refused.
- A web console session keeps the browser on its tunnel when the console writes its own origin
  (A273-O2). The gateway rewrites the origin to the tunnel's in absolute links, form actions,
  `<base>`, scheme-relative and WebSocket URLs, JSON with escaped slashes, the `Refresh`,
  `Link` and `Content-Location` headers, and the `Content-Security-Policy`'s sources. It drops
  the policy's `upgrade-insecure-requests` and `block-all-mixed-content` directives, as it
  already dropped `Strict-Transport-Security`, because the tunnel is plain http on loopback.
  Before this, such a link took the browser off the tunnel, where no gateway signs in or
  records.
- A Windows local-account rotation whose outcome the host lost is settled (A268-O1). The
  generation gets one recovery delivery, and the host settles it by sign-in alone, at most twice
  and within the account's lockout margin, without changing the password again. If the
  successor signs in and the predecessor is refused, the rotation completes with the host's
  proof. If the predecessor still signs in, the generation was never applied: the rotation fails
  with nothing to restore, the account and vault keep the current password, and the next
  rotation starts from the same predecessor. Before this, the rotation stayed prepared for an
  operator. It still does when recovery cannot tell, or the host's agent predates it.
- An AD discovery scan refreshes the hosts bound to the accounts it finds (A267-O1): each
  enabled enrolled-host binding whose account still has the identity it was saved with gets
  its read-only service, task and IIS inventory queued, through the same-transaction outbox
  the host's own **Scan host** uses, at most once per scan, host and account.
- A host account scan reads the authorized keys files sshd reads (A260-L2): the
  `AuthorizedKeysFile` the host's `sshd_config` sets, its `Include` files read in place, with
  `%u`, `%h`, `%U` and `~` expanded per account, or sshd's defaults. An account on a host that
  sets other files names them, and one whose sshd has an `AuthorizedKeysCommand` says so. Keys
  outside `~/.ssh` were missed before, and keys in a file sshd no longer reads were counted.
- MySQL, MongoDB and Redis sessions opened for the browser have a database console (A259-L5), as
  PostgreSQL sessions do: SQL on MySQL, a command on Redis as redis-cli takes it, and a JSON
  command document on MongoDB, each run through the session's gateway, which signs in as the
  session's account and records it. `POST /api/v1/access/sessions/{id}/queries` takes `command`
  beside `sql`.
- A Kubernetes session opened for the browser lists its pods and containers (A259-L4): the
  console's pod form picks from the pods the session's service account can see, in the
  provider's namespace or one you name, instead of typed names. `GET
  /api/v1/access/sessions/{id}/pods` and `trstctl-cli access sessions pods` read the same list
  through the session's gateway, which signs in with the session's token and records it.
- Database gateway sessions verify a private CA with no file on the gateway's host (A256-L1).
  The control plane carries the provider's CA with the session's job, in
  `database_ca_pem` and `database_server_name`: Redis's `redis_tls_ca_ref` and
  `redis_tls_server_name`, and the root file a PostgreSQL or MongoDB administrator DSN names,
  read on the control plane's host. The gateway's PostgreSQL, Redis and MongoDB sign-ins
  verify against it ahead of a root file the session's credential names. A gateway that
  predates the fields ignores them and verifies as before.
- The upgrade preflight has a JSON form and a console panel (A246-L1): `trstctl --upgrade-preflight
  --upgrade-preflight-format json` writes the verdict for a pipeline (format `trstctl.upgrade-preflight.v1`,
  every list present, the same exit code), and the running control plane serves the same verdict for its
  own database at `GET /api/v1/platform/upgrade-preflight` (`trstctl-cli platform upgrade-preflight`) and in
  Upgrade readiness on the Platform page.
- Operation actions run in place (A245-L4): each available retry and rollback in the operations ledger
  carries the exact request it sends and, when its route has one, the preview that reviews it; the
  Operations page reviews and then runs it there, through the route's own checks and approval. A failed
  delivery to an identity that was deployed now retries by renewing through its bound issuer (the
  advertised deploy retry was refused, since no private key is kept to repeat a delivery).
- A destination is verified without an earlier observation (A244-L1): the endpoint verification scheduler
  also probes, for the first time, a deployment target that names its listener (`verify_address`) once it
  has delivered an identity's active certificate there, expecting that certificate, with the target's
  connector and server name. A cloud or appliance destination whose connector reads nothing back no longer
  stays `delivered` for good. The application view shows the endpoint a destination is checked at, or that
  nothing checks it.
- A TOTP provider's seed is replaced through the API (A239-L5): `POST
  /api/v1/secrets/leases/providers/{provider}/totp-seed` (`trstctl secrets leases totp-seed`) takes the
  newly enrolled seed and a current code from it, checks the code (one step of skew), then writes the seed
  as the next version of the provider's `secret://` reference through the secret store's own write path.
  The next lease's code comes from it. A seed in a `file:` reference is replaced in the file. The console's
  TOTP provider view has a Replace the seed form.
- LDAP leases over StartTLS (A239-L3): a generic LDAP provider with `start_tls` connects to the directory's
  plain port (389) and upgrades with StartTLS, verifying the directory's certificate before the
  administrator binds. A refused or failed upgrade ends the connection, never falling back to plaintext.
  Leases carry the `ldap://` URL with `start_tls` set.
- SSH certificates as dynamic-secret leases (A239-L11): an `ssh-certificate` provider gives each lease a fresh
  Ed25519 key pair and a certificate from the control plane's own SSH CA for its role's principals
  (`ssh_roles`) and the lease's lifetime. The key pair is prepared and sealed before the CA signs, so a retry
  certifies the same key. Revoking the lease revokes its key ID on the served KRL; a certificate can't be
  extended, so renewal is refused. The console reveals the lease's private key and certificate apart.
- A machine session can end itself, and a CSI secret volume's session ends with the volume (A238-L7):
  `POST /api/v1/secrets/sessions/self/revoke` (`trstctl-cli secrets sessions end`) revokes the bearer it
  is called with, whatever the session's scopes, and names no session, so it can't end another one. The
  CSI node plugin calls it when a pod's last volume is unpublished, so the session's token stops working
  at once rather than at its expiry; an unreachable control plane never holds up the unpublish. The
  console's session list says when a session ended itself, and otherwise who revoked it.
- Rendered secret files can belong to the application's user (A238-L2): a render template's `owner` and
  `group` (names or numeric IDs) make an agent running as root give the file to them before it is renamed
  into place, so the file never appears with another owner, and every new version keeps them. An agent
  that isn't root, and Windows (where the file's DACL names who reads it), refuse a template naming them.
- A scoped sync definition can be replaced in place (A237-L3): `PUT /api/v1/secrets/scoped-syncs/{id}`,
  `trstctl secrets scoped-syncs replace`, and Edit definition in the console. Replacing used to mean
  removing and defining it again. The replacement takes the same checks as a new definition and keeps
  the same ID and history. Keeping the destination keeps the keys the sync manages there. Moving it
  releases them, so they stay where they are, and the next plan writes the new place. A mode left out
  stays, and leaving the approval-gated mode needs `access:write`.
- Approval-gated convergence for scoped secret syncs (A237-L1): a third mode, `approved`. The control
  plane plans the sync when its sources change, as for `auto`, but applies a plan with changes only
  after the tenant's required number of distinct approvers (members who write in the source's
  environment) approve that exact plan. Until then the definition reads `awaiting_approval` and names
  the request. A manual apply waits for the same kind of approval, and each approval is used once.
  Leaving the mode, or removing an approved sync, needs `access:write`. The plan digest now binds the
  definition's route, rules, mode and author rather than its reconcile bookkeeping, so a waiting plan
  keeps its digest. The console sets the mode and links the request a plan waits for.
- A promotion into a restricted secrets environment needs four-eyes approval (A236-L1). The apply
  writes nothing and names the approval request until other members who hold write there approve
  that exact plan: the tenant's required number of distinct approvers, two by default. The approval
  is consumed with the versions the promotion writes, so it is used once. The console's Promote or
  restore panel names the request and links Approvals. Approval requests for a restricted
  environment's secret changes and promotions are listed to, and decided on the generic route by,
  only the members who hold write there.
- A dynamic-secret provider can be placed in a secrets project environment (A235-L2):
  `secret_environment: "<project>/<environment>"` in its configuration. In a restricted environment
  only the members granted it see the provider and its leases. Only its developers and admins
  issue, renew and revoke them, on the native lease routes, the Vault-compatible creds, sts and lease
  paths and their role listings, and the dynamic-lease rotations. A machine session or the SDK
  agent is held to its principal's grant like a person. To anyone else the provider answers as one
  not configured. A placement naming a missing environment closes the provider. The catalog shows
  each provider's `environment`.
- Secrets projects and their environments can be renamed (A235-L3): `POST
  /api/v1/secrets/projects/{project}/rename` and `.../environments/{environment}/rename` (access:write),
  `trstctl secrets projects rename` and `trstctl secrets projects environments rename`, and a Rename action
  in the console's Projects view. The display name changes; the slug, which every secret name in the
  project begins with, stays, so secrets, references, syncs and member grants are untouched. The same
  name again records nothing.
- A `secret://` reference into a restricted secrets environment is now a read (A235-L2). Only a
  member granted that environment can set one up on any API surface trstctl later redeems by name
  with no caller present. That covers connector targets and inline endpoint destinations,
  notification channels, observers, ticket intake and MDM poll schedules, DNS-01 provider
  credentials, MDM SCEP challenge keys, ACME EAB keys, discovery sources and secret-sync workload
  proofs. Before, a caller with an integration's permission could have trstctl send a restricted
  secret to an endpoint the same request named. Every spelling a redeemer resolves is checked, on
  create and on every update. The refusal (403) does not reveal whether the secret exists. A
  leaked-secret move naming a restricted secret now answers as for a missing one.
- A secrets project's admins manage its membership (A235-L1). A caller holding secrets:write and the
  project's admin role grants and revokes that project's members without access:write, within its own
  grant: an admin restricted to some environments grants only those environments, cannot grant every
  environment, and cannot change or revoke a member whose grant reaches past its own. access:write keeps
  full control, even on its own; projects and environments still change under it; and a secrets:write
  token still cannot grant itself an environment. The member routes admit the computed
  `secrets:members.manage` predicate (access:write or secrets:write, never grantable), and the tenant's
  ABAC policy is evaluated against the permission the caller acts under. The project view says whether
  the caller can manage members, and the console shows the grant form and revoke buttons accordingly.
- The SPIRE upstream authority plugin implements `SubscribeToLocalBundle` (A205-L3). SPIRE Server
  receives the trust domain's bundle as trstctl sees it, the root the configured `ca_authority_id`
  chains to and the JWT keys the tenant's SPIRE servers and trstctl publish, and the open stream sends
  it again when a key is published or the root changes, so SPIRE keeps its local bundle in step
  without minting or rotating. A trstctl without JWT key publication contributes the root alone.
- The SPIRE upstream JWT key set carries trstctl's own SPIFFE JWT authority (A205-L2).
  `/api/v1/spiffe/upstream-jwt-keys` (and so every SPIRE server running the trstctl upstream authority
  plugin) now lists the workload JWT keys trstctl publishes, the signing key, a next key published ahead
  of a rotation and a retiring one until it retires, as `published_by: trstctl-spiffe-jwt-authority`, so
  SPIRE servers sharing the trust domain verify the JWT-SVIDs trstctl issues. `published_at` is absent
  for trstctl's first-generation key.
- The Vault/OpenBao-compatible shim serves the dynamic engines' configuration paths read-only
  (A203-L2). `vault list database/roles`, `vault read database/roles/<role>`, the same for `aws/roles`
  and `kubernetes/roles`, and `vault list database/config` / `vault read database/config/<name>` answer
  from the configured providers (at the engine mount or a provider's own): a role's provider and
  lifetimes, a connection's plugin, allowed roles and readiness, never a DSN, key or token. Writing or
  deleting them is refused with `405`, naming the configuration file where providers and roles live; a
  cubbyhole path with the same shape still belongs to the cubbyhole.
- AWS Systems Manager Parameter Store reads its state back (A202-L1). The `aws-parameter-store`
  sync target lists parameters with `GetParametersByPath`, reads one with `GetParameter`
  (`WithDecryption`, compared as a SHA-256 digest or in constant time, never returned) and deletes
  with `DeleteParameter`, so it takes scoped syncs: a plan finds a parameter changed outside trstctl
  (`update`) and the apply writes the source value back, and an auto scoped sync's drift check does
  that with nobody applying. A delivery whose outcome was lost settles by reading the parameter instead
  of keeping the lane closed for an operator. Parameter names are checked against SSM's rules.
- Dynamic-lease rotation runs on a schedule (A201-L1). `POST /api/v1/secrets/rotation-schedules`
  accepts `dynamic-lease:<provider>` with `ttl_seconds`, checked like an on-demand dynamic-lease
  rotation before anything is stored (TTL required and within the provider's maximum, a provider that
  issues and verifies the role's leases, `old_ref` the role's active lease); each due edge queues the
  durable dynamic-lease command, which issues a lease of that TTL, publishes it and revokes the lease
  the last command left live. The schedule carries `ttl_seconds` (migration 0446); the console's
  schedule form asks for the lease TTL for a dynamic-lease provider and the schedule table names it.
- The Helm chart runs the HSM signer image (A200-L3). `signer.hsm.enabled` runs the signer from
  `trstctl-signer-hsm` (by digest, by tag, or by the chart's own tag) and its cgo
  `/usr/local/bin/trstctl-signer-hsm` in the sidecar and the isolated topology, mounting the vendor's
  PKCS#11 module and client files from `signer.hsm.volumes`/`volumeMounts`; the control plane keeps
  the main image. `externalKMS.provider=pkcs11` with the shipped adapter now fails at template time
  without it, instead of a signer whose static adapter refuses PKCS#11 at startup.
- `trstctl-signer --rewrap-keystore` moves a key store the local KEK sealed onto the external KMS/HSM
  adapter (A200-L2). With the signer stopped, it probes the adapter, copies the key store beside
  itself with every sealed file's data key moved from the KEK to the adapter (keys, journals, import
  seeds, KEM custody; payloads never opened), checks each data key comes back unchanged, every key
  opens under the adapter and the store did not change meanwhile, then keeps the original as
  `<keystore>.pre-rewrap-<UTC time>` and puts the re-wrapped copy in its place. Any failure leaves
  the key store as it was. Before, external custody could only start from an empty key store.
- The KMS wrap adapter reads AWS credentials from the platform (A200-L1). `trstctl-kms-wrap`'s
  `aws.credential_source` takes `web_identity` (IRSA: the projected token exchanged at STS),
  `container` (ECS task roles, EKS Pod Identity), `instance_metadata` (an EC2 instance role over
  IMDSv2) or `default_chain` (those three in the AWS SDKs' order), reading the environment the AWS
  SDKs read; `static` (an access key with its secret file) stays the default. Metadata endpoints are
  reached only by a client pinned to AWS's link-local credential addresses or a loopback agent, with
  no proxy and no redirects. The Helm chart's isolated signer can run under its own service account
  (`signer.serviceAccount`), so an IRSA role annotation reaches the signer and not the control plane.
- `trstctl-agent --edge-attest` writes the PKCS#11 lane's mint body (A175-L2). With a PKCS#11 edge key
  and `--edge-pkcs11-attestation-labels`, it reads the token's attestation chain of the key again,
  checks the leaf certifies the CSR's key, and writes a mode-0600 body with `key_provider: pkcs11`,
  the CSR and `pkcs11_attestation_chain_der` for `trstctl-cli edge delegations mint -f`; before, it
  refused every key but a TPM's and the operator assembled the PKCS#11 body by hand. `--edge-csr`
  with a PKCS#11 key now points at that step instead of the TPM one. Proven through the agent CLI
  against SoftHSM holding a stand-in vendor chain.
- Image annotations reach registries behind a token server and registries without the OCI referrers
  API (A174-L2). A registry's 401 Bearer challenge is answered with a token from its realm (the
  annotation connection's `username_ref` and token as basic credentials), reused for the repository;
  and when the registry does not answer the referrer's put with `OCI-Subject` (the CNCF Distribution
  `registry:2` image, for one), the referrer is also listed in the referrers tag schema's
  `sha256-<subject>` index, and taken out of it when the finding is resolved, so tools that look up an
  image's referrers find it.
- The discovery findings list filters by fingerprint (A172-L2). `GET /api/v1/discovery/findings?fingerprint=`
  (CLI `trstctl-cli discovery findings list --fingerprint`) returns every finding that names one
  certificate or key, whatever its kind, source or run, accepting the colon-separated hex certificate
  viewers show; an index keeps it from scanning the tenant's findings. A finding's detail in Discover
  links to every finding with its fingerprint, and the list says while it is narrowed.
- An application blocked at the provider can be unblocked from the same finding (A171-L1). `POST
  /api/v1/discovery/findings/{id}/oauth-grant/unblock` (`trstctl-cli discovery findings
  unblock-oauth-app`) reactivates the Okta application or re-enables the Entra service principal through
  the source's admin connection, reads the change back, and records it on the finding; the finding panel
  offers **Unblock app at provider** once a block is confirmed. Google Workspace, whose API cannot block
  an app, cannot unblock one either.
- OAuth provider actions read the change back before recording it (A170-L2). After the provider
  confirms a revoke, block or admin-consent revoke, trstctl reads the grants, tokens or application back
  (up to three reads a second apart) and records the read back in the finding's detail; a grant still
  listed or an app still active after the provider's confirmation is recorded failed, naming what is left,
  instead of confirmed. Before, the acknowledgement alone was recorded and only the next discovery run
  re-checked.
- A Microsoft Entra application's admin consent for every user can be revoked at the provider
  (A170-L1). A Graph grant with consent type `AllPrincipals` names no user, so revoking it used to be
  refused ("block the application instead"); the revoke route now deletes exactly that tenant-wide
  admin consent for the application, leaving each user's own grant, and the Discovery finding panel
  offers **Revoke admin consent at provider** with a confirmation that says so.
- GCP Cloud KMS managed-key custody can run on a workload identity instead of a static bearer token
  (A169-L1). `managed_keys.gcp.workload_identity` (or `TRSTCTL_MANAGED_KEYS_GCP_WORKLOAD_*`) names the
  workload identity pool provider and the projected OIDC token file; the isolated signer exchanges that
  token at GCP Security Token Service, optionally impersonates a service account, and reuses each
  short-lived access token from locked memory until shortly before it expires. Exactly one of the
  static token and the workload identity may be set.
- Reconciliation rounds can compare a Google Cloud KMS key ring and an Azure Key Vault vault with
  trstctl's managed-key record (A168-L1). New `gcpkms` and `azurekv` authority sources read a ring's
  keys and versions, or a vault's keys, versions, version public keys and deleted keys (read-only, with
  a bearer token from a file), and assert the keys trstctl created by the identity its record uses; the
  `managed_keys` authority now serves `gcp-kms` and `azure-key-vault`. A round witnesses a key only the
  provider holds, one only the record holds, and a key whose state drifted. trstctl also labels (Cloud
  KMS) or tags (Key Vault) each key it creates there with its tenant, so tenants sharing a ring or vault
  see only their own keys.
- A scheduled Cloud network paths run re-validates the exposure posture (A167-L4). A full run of a
  `cloud_network_path` source, including every run its schedule queues, now validates the endpoints
  the exposure posture names — at most 50 a run, records never validated first and then the longest
  unchecked — and records each address's verdict under the run, so a firewall change reaches the
  posture without an operator asking. Before, every full run failed and pointed at the posture.
  Each source now keeps its own latest verdict per address, and one whose account holds the address
  outranks another account's "not in account". The exposure panel says a schedule does this.
- An open cloud attack path raises the record's exposure finding (A167-L3). When a cloud account
  confirms the internet reaches an exposed endpoint, the finding becomes at least high, critical when
  the endpoint also authenticates weakly, uses insecure transport or admits wildcard reachability; it
  gains the `cloud_path_open` finding type, a risk score to match and a recommendation to close the
  rule the Cloud path names, and the posture automation's rules see the same. A blocked verdict lowers
  nothing, since paths the adapters do not read yet may still reach the endpoint.
- Attack-path validation can read an Azure subscription (A167-L1). A `cloud_network_path` source
  with `provider: azure-network` names the subscription and a token reference, and validating
  exposed endpoints through it reads, from Azure Resource Manager, the public IP holding each
  address, its network interface, the subnet, both network security groups and the subnet's route
  table (read-only; the public IP list is paged and a `nextLink` that leaves the endpoint is
  refused). The subnet's group and then the interface's must each admit the internet with their
  first matching rule by priority, a Standard public IP no group opens stays closed, and a route
  that sends the internet-wide range to an appliance breaks the reply. The verdict names the group,
  route table or public IP that decided, with new `network_security_group` and `public_ip` stages,
  and the Risk page labels them.
- Attack-path validation can read a Google Cloud project (A167-L1). A `cloud_network_path` source
  with `provider: gcp-compute` names the project and a token reference, and validating exposed
  endpoints through it lists the project's instances, VPC firewall rules and routes (read-only,
  every page) and judges each external address the way the VPC does: the lowest-priority applicable
  route for the internet must lead to the default internet gateway, and the lowest-priority ingress
  firewall rule that applies to the instance and names the internet-wide range decides, a deny
  winning a tie and the network's implied ingress deny standing behind them all. The verdict names
  the firewall rule that admits the internet, or the denying rule, route or network that blocks it,
  with a new `firewall` stage; the Risk page's Cloud path column now reads, for example, "Blocked at
  prod (firewall)" with the evaluator's reason beneath, so a network whose implied deny decided is
  never shown as a rule.
- An AWS Certificate Manager target can name the Elastic Load Balancing listener it serves
  (`listener_arn`) and then roll back (A166-L2). ACM re-imports in place under one ARN and keeps no
  previous version, so such a target instead imports each deploy as a new certificate tagged with its
  fingerprint and points the listener's default certificate at it; the predecessor stays in the
  account, a rollback points the listener back at it (found by its tag and confirmed by reading the
  certificate back, uploading nothing), and a readback reports the certificate the listener serves.
  Requests to both services are signed with SigV4. A target without a listener deploys in place as
  before and still cannot roll back. With this, no connector family remains an E1 architecture
  exception.
- An Azure Key Vault target can be rolled back (A166-L1). Key Vault keeps every imported version but
  serves the newest by name, so the rollback finds the predecessor's version by its fingerprint, reads
  that version's retained secret and imports it again as the newest version; the key comes from the
  vault's own copy, and trstctl's imports now mark the key exportable (Key Vault's default for an
  import) so it can. The rollback runs where the family's deploys run (the control plane, or the
  tenant's network relay), its receipt says the predecessor was re-imported from the vault's copy, and
  the connector now reads back the version the vault serves, so Key Vault completes its parity gates
  like GCP Certificate Manager. Before, Key Vault rollbacks were refused.
- A rogue certificate's confirmed revocation at its issuer resolves its Certificate Transparency
  finding (A163-L2). The finding's triage becomes remediated, recorded by trstctl with the issuer's
  confirmation as the evidence of the fix, so an operator no longer resolves it by hand; a redelivery
  records nothing more, and a finding an operator had claimed as managed or dismissed keeps that
  decision.
- A rogue certificate the tenant's own AD CS issued outside trstctl, seen only in Certificate
  Transparency, can be revoked at that CA (A163-L1). An AD CS issuer that names a revocation relay is
  now listed as revoking by serial: Revoke at issuer hands the serial to the relay, which runs
  `certutil -revoke`, publishes a CRL and reads the row back, and the finding reads revoked at the
  issuer only from that checked report. The API refuses, and the console does not offer, a reason
  certutil cannot record.
- An ACME client can revoke a certificate trstctl's ACME issued through a profile's upstream CA
  (A162-L4). `revokeCert` of such a certificate used to fail as a server error ("issuer revocation is
  not supported"). Once RFC 8555 §7.6 authorizes the request, trstctl now queues the same exact
  revocation at the upstream that an operator's bulk revocation queues (for AD CS, through the
  issuer's revocation relay), answers 200, records the certificate revoked only when the CA confirms,
  and never lists the upstream's serial on its own CRL. At an upstream configured without a way to
  revoke, the client gets `unauthorized` (403) saying why.
- A Jamf poll schedule can name a Jamf Pro API client instead of a hand-rotated bearer (A156-L1).
  The schedule stores the API client's ID and a secret reference to its client secret; the network
  relay redeems the secret per attempt and exchanges it at the same Jamf Pro server's
  `/api/oauth/token` for an access token that lives only in memory, for the inventory read and for
  an approved device check-in alike. The API refuses an API client on an Intune schedule, a
  malformed client ID, or a plain http server its secret would cross in clear. The console's MDM
  schedule form takes the client ID for Jamf, shows it in the review and checks the readback; the
  form no longer throws while a base URL is retyped after a failed review.
- A white-labeled console shows "Powered by trstctl" beside the Provider customer's brand (MSP-1,
  part 1). The console now carries the brand the control plane resolves for the customer's host:
  the sign-in page shows the customer's logo, product name and login message, and every page's
  header shows the logo and product name, with the brand's design-token colors applied (only
  `--`-named tokens with plain values). Beside the brand, above the fold on the sign-in page and in
  the header on every page, it shows "Powered by trstctl" on fixed trstctl styling that no brand
  field or token override can change or hide, at well over 4.5:1 contrast in both themes.
- Every other surface that shows a white-label brand says "Powered by trstctl" too (MSP-1, part 2).
  A branded email carries the line in its header; the customer assurance report shows it beside
  the brand on its cover and at the foot of every printed page, in a repeating footer row that
  never covers a row; a white-labeled customer's Slack, Teams and email notifications carry it as
  a line and its webhook payloads as `powered_by`; and Slack approval requests end with it. One
  rule decides when a brand is white-label (any field differs from the built-in brand, so a brand
  that changes only colors or email strings counts), and the console's public brand route uses it
  too. The provider brand write now refuses a field the brand document does not have, naming the
  fields it does have, instead of saving the rest and dropping it silently; no field turns the
  line off. A branded email whose brand sets no product name keeps its logo and footer.
- The console sets PKCS#11 vendor attestation for an edge segment (A175-L1). A segment's PKCS#11
  token vendor roots and the requirement that a PKCS#11 request carry the token's attestation could be
  set only through the API or CLI. When PKCS#11 custody is allowed, the edge segment form takes the
  vendor root certificates and the requirement (refusing a requirement with no root before review),
  the review shows them, and the segment table shows each segment's vendor roots and whether they are
  required.
- The Posture page imports a CBOM (X6-L4). A CycloneDX CBOM from a vendor, a source scan or an image
  scan could be imported only through the API or CLI. Import a CBOM takes the source kind and name and
  a JSON file, sends the file's bytes as they are (so the same file again changes nothing, as from the
  CLI), keeps one idempotency key across a retry, says what the import recorded or that it changed
  nothing, and refreshes the CBOM inventory.
- The Migration page shows the observed-traffic gate (X3-L3). A run that requires observed traffic
  advances a wave only when an observer sees new connections at every member, but the console showed
  only the halt reason. Run history now says the run is gated and for how long a member may wait,
  shows why a run paused, and gives each member its observed-traffic state: observed, waiting since
  it was verified live, or not seen in the window.
- The console starts a planned CA switch (P3-L3). A migration run that revokes each predecessor once
  its successor is verified live could be started only through the API or CLI. The Migration page's
  plan now offers "Revoke each predecessor once its successor is verified live", shows the choice in
  the plan review and the start summary, sends `revoke_predecessors` only when chosen, and says on a
  run that it revokes predecessors.
- The console shows device first-boot batches (P12-L3). Factory batches were reachable only through
  the API and CLI. The CA hierarchy page's Device first-boot batches panel lists each batch's quota,
  birth lifetime and reconciled births, shows a batch's devices with their birth certificates and
  enrollment, and, for an issuer, creates a batch under an active edge delegation, saves the station
  manifest and reconciles a station's journal pasted as PEM, each request with its own idempotency key.
- A domain-validation policy can require dns-persist-01 (P1-L3). A tenant's DNS-01 provider config
  names the methods its zone's ACME orders may use, but only http-01, dns-01 and tls-alpn-01 could be
  saved, and the served policy dropped anything else, so persistent DNS validation was never offered
  under a policy. `allowed_methods` now takes `dns-persist-01` in the API and on the Protocols page,
  and the zone's names, wildcards included (their standing record carries `policy=wildcard`), are
  then offered that challenge.
- Misuse findings are listed, not only alerted (M2-L1). Enterprise governance raises an alert
  for each misuse finding within a per-tenant hourly budget, and a finding past the budget was
  recorded but could be read nowhere. `GET /api/v1/misuse/findings` (audit:read) lists the
  caller's own tenant's findings, newest first and a page at a time, optionally by rule or
  token, and the Risk page shows them as Token misuse findings, saying which ones raised no
  alert. An index on the findings' event sequence keeps every page a short index scan.
- The Agents page says what a relay's job connections may reach (A190-L1). The egress policy a
  relay follows (`--relay-egress-allow`) showed only in the line the relay prints when it starts.
  A relay that claims jobs now reports it on its heartbeat (agent.heartbeat v8), and `GET
  /api/v1/agents` serves it as `reported_relay_egress`: whether an allowlist is set and what it
  lists, at most 64 entries, marked `truncated` when the recorded list is shorter than the
  relay's, and never read as no allowlist when it was cut short. The Agents page shows the list,
  or warns that a relay without one may reach any address its network reaches.
- Command rules on network devices read the lines typed in an interactive shell (A270-L1). A
  ruled device session used to refuse a shell, since only exec commands were read. Now every key
  reaches the device as typed, and each line's submission (Enter, or Ctrl-Z) waits for the rules:
  an allowed line runs, a refused one is killed at the device with Ctrl-U and runs nothing, is
  recorded as blocked evidence like an exec command, and the client is told. The gateway follows
  erase, kill-line and erase-word keys; a line edited with history recall, completion or cursor
  keys is refused as uninspectable.
- A failed access review revocation is retried (Q1-L2). It used to stay failed: nothing retried it,
  and a retry under the decision's own key could not work, because PAM refuses to retry a failed
  revocation under the key that failed. The leader's reconcile now retries on its own, waiting as
  long as the revocation has been failing (5 minutes to 6 hours) and stopping a week after the first
  request; an operator retries at any time with a reason through
  `POST /api/v1/access/reviews/{id}/items/{item_id}/revocation-retry` (access:write), the CLI's
  `access reviews retry-revocation`, or Retry revocation on the item. Every attempt has its own
  idempotency key, and the item records who retried and why.
- A revocation waiting on an AD CS relay says why (A162-L5). An `adcs` issuer revokes through its
  `revocation_relay`, and until that relay reports, the certificate stays active and the delivery
  waits without spending its retries, which showed only as a deferred job. `GET
  /api/v1/revocation/relay-waits` (certs:read) lists each revocation the relay has not finished:
  the relay's name (also for a relay that has never connected), its presence and last heartbeat,
  waiting or running, the attempt number and the last failed attempt's reason. The Revocation
  center lists them, and a queued certificate shows its own wait.
- A failed host renewal says why in plain words, with one retry (A36's console part). The
  `renewal_failed` alert leads with the cause, one of a closed set read from the control
  plane's own records (the certificate authority's error class for the job's request, or
  whether a certificate was signed), and names Retry renewal. `GET /api/v1/identities/{id}`
  carries it as `renewal_failure` while the identity is `renewal_failed`; the identity view
  shows "The last renewal failed. <cause>" and offers Retry renewal as its one action.
- Enterprise-scale harness (A266; build list section 35, item 4): `make perf-scale` and `scripts/perf/run-scale.sh`
  (`--inventory`, `--renewals`, `--clients`, `--chunk`, `--seed`, `--fleet-lifetime`, `--timeout`, `--out`) boot the
  local eval stack and drive it through the API: an inventory generated from the seed and imported through the
  switching kit, a fleet of managed identities under a short-lived profile, each deployed to its own ACM target, and a
  renewal storm the scheduler finds on the real clock once the fleet's renewal windows open, delivered by the
  runtime's dispatcher. The JSON receipt (`trstctl.scale.v1`) records each phase's throughput and latency, the storm's
  drain time, outbox depth and read latency, component resources and every correctness gap, and the run fails on any
  gap. The served scale plan (`GET /api/v1/scale/orchestration`) names it as the `enterprise-scale` release gate with
  its receipt `scripts/perf/artifacts/scale-local-baseline.json`: one Mac, 100,000 certificates recorded at 164 a
  second and a 2,000-renewal storm delivered in 393 s. CI: `a266-scale-smoke` (3,000 certificates, a 40-renewal
  storm).
- Posture rollout across hosts proven (A176): a lab test runs the Envoy PQC fixture twice, each copy a container host
  with its own enrolled agent, and one migration run rolls the TLS posture out to both — each job pinned to its own
  host's agent, each readback signed by it — and back.
- Host TLS session observer (X5): an agent granted the new `session-observer` role (`agents:relay.grant`; migration
  0435 lets bootstrap tokens grant it) and started with `--observe-tls-sessions` attaches eBPF probes to its host's
  OpenSSL 3 libraries (`--observe-tls-libraries`) and reports, for each TLS handshake on the host, the process, side,
  version, cipher suite, key-exchange group, HelloRetryRequest and the peer's certificate facts — the certificate TLS
  1.3 encrypts on the wire — as `tls_session` findings under the `tls-session-observer` source
  (`--observe-tls-report-interval`). The probes copy only plaintext handshake records and the certificates libssl
  parses during a handshake, never application data. The server accepts the source only from a certificate carrying
  the role and `tls_session` from no other source; removing the role detaches the probes. Coverage: `host-tls-sessions`
  is an observed class. Console: the **Session observer** role. Linux 5.17+ (x86-64, arm64), BPF privileges, host PID
  namespace. CI: `x5-session-observer` (ubuntu-latest).
- Windows signing adapter (P9; build list section 35, item 1): `trstctl-ksp.dll`, a CNG key storage provider in
  `clients/signing/ksp`, offers trstctl code-signing keys to signtool and other CNG tools as key containers
  (`TRSTCTL_KSP_KEYS`; ECDSA P-256, and RSA with PKCS #1 v1.5, over SHA-256). The key never leaves the signer: each
  signature goes through `POST /api/v1/code-signing/sign`, is checked against the key's certificate, and is refused
  as `NTE_PERM` when trstctl refuses it; the provider creates, imports and exports no private key.
  `TRSTCTL_KSP_TRACE=1` logs each call. `trstctl-ksp-register install|status|uninstall` copies the DLL into System32
  and registers it with CNG. `make signing-ksp-windows` cross-compiles both with MinGW-w64 and checks the DLL's
  exports and imports. CI: `p9-ksp-windows-build` (cross-compile) and `p9-windows-signtool` (windows-latest: signtool
  signs two executables through the provider and `signtool verify /pa` accepts them).
- Recording uploads through the outbox with backpressure (A278 part 3): a gateway's chunk is sealed and staged with its
  outbox entry (`pam.recording.store`) in one transaction and the upload returns at once; a bounded in-process uploader
  and the outbox worker store chunks in order (an earlier staged chunk defers a later one without spending an attempt;
  an unanswering store defers before any write; exhausted attempts defer instead of dead-lettering); the recording
  seals once none wait. Past `pam.recording_staging_bytes` (default 16 MiB a session, sixteen times that a tenant) an
  upload is refused with RESOURCE_EXHAUSTED and the gateway retries. Migration 0434 (`pam_recording_uploads`, delivery
  state: erased with its tenant, not rebuilt or snapshotted). The recording index gains `pending_chunks`; console: the
  session detail's **Recording** row.
- Drained gateway upgrades (A278 part 2): `agent.upgrade` and `agent.self_check` admit the gateway role, so access
  gateways started with `--self-upgrade` take staged upgrades. A pooled gateway with an upgrade queued reads
  `upgrade_pending` and draining (no new sessions); the agent channel withholds its upgrade job while it owns live
  sessions, and the campaign waits for it instead of scoring it silent. Console: **Draining for upgrade**.
- Gateway pools (A278 part 1): `GET|PUT|DELETE /api/v1/access/gateway-pools[/{name}]` (OpenAPI 796 -> 799; CLI
  `access gateway-pools list|save|delete`, 863 -> 866; migration 0433, snapshot format 111). Gateways of a pool share
  their targets' sessions: a session starts on the healthy, undrained member with the fewest live sessions, which owns
  it (its job is claimable by that gateway alone; a member's server certificate also covers its own pool address, and
  a pooled member may certify SSH session keys for its pool's targets). A member that misses heartbeats past
  `pam.gateway_lost_after` (default `2m`, at least `30s`) is lost: new sessions go to the others and its live sessions
  are revoked by `trstctl:gateway-health`, reading `gateway_lost: true` with `uncertain_until` their deadline. Console:
  the **Gateway pools** panel (health, live sessions, drain/resume, create/edit/delete) and "Gateway lost" on a
  session's detail.
- High-risk access templates need a fresh sign-in (A277 part 2): `reauthenticate_within_seconds` (60-3600; migration
  0432, snapshot format 110) refuses a session, emergency session or check-out reveal through the template unless the
  caller's console sign-in is that recent — `401` with an RFC 9470 step-up challenge
  (`WWW-Authenticate: Bearer error="insufficient_user_authentication", max_age=...`); API tokens never satisfy it.
  Browser sessions now carry the time the person authenticated (an OIDC id_token's `auth_time`, rejected when in the
  future; the moment a directory password bound). `/auth/login?reauth=1` asks the provider for `prompt=login` and
  `max_age=0` and refuses a callback whose `auth_time` predates it. Console: the access dialog and check-out panel
  answer the challenge with **Sign in again** in its own window (`/reauthenticated` reports back on this origin), the
  login page's fresh sign-in mode offers only OIDC and directory sign-in, and templates gain a **Fresh sign-in**
  column.
- Slack approvals over Socket Mode (A277 part 1): `slack_app.app_token_ref` makes trstctl open Slack's Socket Mode
  connection itself (outbound only) and stop serving the Slack request URLs; slash commands and button presses arrive
  over it. Buttons now carry trstctl-signed decisions (request, intent digest, action, nonce, expiry under the
  deployment key): an altered or expired decision is refused, and each linked member's use is recorded once, so a
  replay is refused (migration 0431 admits the `decision` purpose). `app_token_ref` and `signing_secret_ref` are
  exclusive; one of them is required.
- Privileged account certification (A276 part 3): access reviews generate from `"source": "pam_accounts"` — brokered
  accounts with owner, roles, template and open flags; template approver lists and quorums; approvers without a
  template; emergency responders. A revoke disables the account. `GET /api/v1/access/reviews/{id}/result`
  (`getNHIReviewResult`, OpenAPI 795 -> 796; CLI `access reviews result`, 862 -> 863) signs a completed campaign's
  result with the audit key; `pam.certification_interval` / `pam.certification_reviewer` start campaigns
  periodically. Console: the review source option and **Download the signed result**.
- Orphaned and unused accounts (A276 part 2): brokered accounts are flagged orphaned (no owner, owner deleted, owner
  offboarded) or unused past `pam.unused_after` (default 90 days) by the PAM worker or `POST
  /api/v1/access/account-flags/scan`; `reassign` and `rotate_disable` actions are proposed for approval, applied once
  with the approval consumed, and read back on the flag and the target. Migration 0430, snapshot format 109, CLI
  `access account-flags list|scan|propose|apply` (CLI 858 -> 862, OpenAPI 791 -> 795), console **Orphaned and unused
  accounts**.
- Owners of brokered accounts (A276 part 1): every privileged access target is an NHI inventory record
  (`pam-account/<type>/<id>`, kind `privileged_account`, `privileged_account_records` in the record summary), so
  ownership assignments name its owner; targets read `owner_id` back; the console's targets table shows owners and
  assigns them.
- Recording search (A275 part 3): `GET /api/v1/access/recordings/search` (`searchPAMRecordings`, OpenAPI 790 -> 791),
  `trstctl access recordings search` (CLI 857 -> 858) and the console's **Search session recordings** search the tenant's
  recordings — SSH commands and output, SQL statements and results, desktop indexes; never typed input — within bounds,
  with masked results; every search is recorded as `pam.recording.searched` with its query masked.
- Risk categories (A275 part 2): command rules for PostgreSQL, MySQL and SSH can name `CREDENTIAL_READ`,
  `AUDIT_TAMPERING`, `BULK_DELETE` and `PRIVILEGE_CHANGE` (lowercase for SSH), which the gateway reads from the
  statement's tokens or the command's programs, flags, paths and redirections (through `sudo`-style wrappers); only
  the category name leaves the gateway. Any effect applies: alert, block or review. The console groups them apart
  from operation names.
- Session risk alerts (A275 part 1): command rules gain the `alert` effect with a `warning` or `critical` severity. A
  matching command runs once its `alerted` decision is durable, and its projection queues a `pam.session.risk` alert on
  the `notification.risk` channels naming the operations, target, person, rule and action, with the console link
  `/admin/access?session=<id>` that opens the session and its recording; the recording marks the action. The console's
  rule editor offers Alert and its severity, session actions show "Alerted; allowed to run", and the access page opens
  a linked session.
- Bypass detection on MySQL (A274 part 3): a MySQL connection, dated when a run first sees it, keeps one fingerprint
  while later runs see it still open (its connection id and the server's start), so a held outside connection raises
  one finding and one recorded sign-in rather than one per run; served proof against MySQL 8.4.
- Recorded sign-ins (A274 part 2): every sign-in bypass detection reads is recorded, metadata only, with the verdict of
  the run that first read it (what explained it, or nothing); `GET /api/v1/access/signins` (`listPAMSignIns`, OpenAPI
  789 -> 790 operations), `trstctl access signins list` (CLI 856 -> 857 commands) and the console's **Sign-ins to
  managed accounts** list them; `pam.signin_retention` (default 90 days) purges them while their findings stay.
- Bypass detection (A274 part 1): a `pam_signin` discovery source reads a provider's managed accounts' sign-ins through
  its administrator connection (sshd journal and auth logs, Windows logon events over OpenSSH, PostgreSQL, MySQL and SQL
  Server current sessions), explains each by a session, check-out, rotation or health check, and records each
  unexplained one as a `compromised_credential` finding. Discovery source catalog 25 -> 26 kinds; the console's
  Discovery source form creates it.
- Gateway sessions from the console (A273 console): the privileged session dialog requests every gateway session type
  (Redis, MySQL, MongoDB, ClickHouse, Snowflake, cloud APIs, the AWS console, remote desktop, network devices, web
  consoles), not only PostgreSQL, SSH and Kubernetes; an opened gateway session shows the CLI connect command and its
  one-time gateway ticket on request. The browser option is offered only for the types the browser opens itself.
- Emergency access (A258 console): an Emergency responders panel names the responders; the session dialog opens a
  session at once as a named responder after a confirmation that every approver is notified (a reason is required);
  post-incident reviews are recorded from the emergency grants table.
- Internal web admin consoles (A273 fix): the published session request, approval, activation and emergency session
  schemas admit `webconsole`, which the API already served.
- Break-glass accounts (A272 console): the access targets panel registers `breakglass` targets; a new Break-glass
  accounts panel releases one as a named responder after a confirmation that every approver is notified, shows its
  username, password, one-time code and hardware key holders once, checks it in, and lists emergency grants with another
  approver's post-incident review. Reviewed check-outs no longer offer break-glass or web console accounts.
- Accounts rotated in place (A271 console): the access targets panel registers `account` targets — an `esxi`,
  `vcenter-sso`, `redfish` or network device provider and one account secret, with no gateway fields — for check-out.
- Windows local administrator accounts (A268 console): the access targets panel registers `windows_local` targets — a
  native `windows` provider and one account secret, with no gateway fields — for check-out.
- Internal web admin consoles (A273 part 3): the console registers `webconsole` targets (account secret, https origin,
  CA, certificate name) and sets an access template's web sign-in (mode, sign-in page and fields or header, browser
  cookies). The served proof can hold its session open for a real browser (`TRSTCTL_A273_BROWSER_DIR`).
- Internal web admin consoles (A273 part 2): `webconsole` access targets vault a console's account and name its route
  (`web`: origin, CA, server name; loopback only with `pam.web_console_allow_loopback`); access templates set
  `web_sign_in` (`form`, `header` or `basic`, and `browser_cookies`), bound into the reviewed request and kept on the
  session; `trstctl access sessions connect` prints the address to open in a browser. The account cannot be checked out.
  The gateway refuses a console name that resolves to its own host or a link-local address. Migration 0428.
- Internal web admin consoles (A273 part 1): the access gateway serves `webconsole` sessions (agent job kind
  `access.gateway.session.web.v1`): it signs in for the operator through the console's own sign-in form, a header token or
  HTTP basic authentication, keeps the console's cookies, masks the credential out of every page and records each request
  and response, masked. The browser never receives the credential.
- Break-glass identity provider accounts (A272 part 3): the credential health worker checks each break-glass account's
  vaulted password once per interval with the identity provider's non-interactive sign-in (Okta, Entra ID; Google reads
  not supported) and never repeats a refused password, so a check never trips a lockout.
- Break-glass identity provider accounts (A272 part 2): `breakglass` access targets are released only through emergency
  access (`POST /api/v1/access/emergency-checkouts`, `trstctl access emergency checkout`): a named responder, once, every
  approver notified, the password plus the current TOTP code of the account's `totp` provider (never the seed), the
  hardware security key holders the provider records (`totp_providers`, `hardware_key_holders`); check-in rotates it. New
  event `pam.checkout.emergency_released`; migration 0427. OpenAPI census 788 -> 789, CLI 855 -> 856.
- Break-glass identity provider accounts (A272 part 1): `okta-user`, `entra-user` and `google-workspace-user`
  dynamic-secret providers rotate super administrator passwords through each provider's administration API, proved by one
  non-interactive sign-in where the provider has one (never retried). Provider catalog 53 -> 56 recipes.
- Account check-outs (A271 part 4): `account` access targets vault an account its provider rotates in place (ESXi,
  vCenter single sign-on, Redfish controllers, network devices); they are checked out, never opened as sessions, and
  check-in rotates them. Migration 0426.
- Hypervisors (A271 part 3): a `vcenter-sso` dynamic-secret provider resets vCenter single sign-on users' passwords
  with `dir-cli` in the appliance's root shell (administrator password only at its prompt) and proves each reset with a
  vSphere Automation API session; discovery lists the SSO Administrators group. New config field `sso_admin`. Provider
  catalog 52 -> 53 recipes.
- Hypervisors (A271 part 2): an `esxi` dynamic-secret provider rotates ESXi local account passwords through the vSphere
  Web Services API (`UpdateUser`, proved by signing in), never `vpxuser` or `dcui`, single-phase with acknowledgement and
  rollback; discovery lists local users with their roles. Provider catalog 51 -> 52 recipes.
- Server management controllers (A271 part 1): a `redfish` dynamic-secret provider rotates controller account passwords
  through Redfish's AccountService (HPE iLO first), proved by a new session on the new password, single-phase with
  acknowledgement and rollback; discovery lists accounts with their RoleId. Provider catalog 50 -> 51 recipes.
- Network devices (A270 part 3): `netdevice` access targets broker SSH sessions to a device account its provider rotates;
  the gateway signs in with the vaulted password (new job kinds `access.gateway.session.netdevice.v1` and
  `access.gateway.session.rules.netdevice.v1`), sessions are recorded, and `netdevice` command rules block device verbs
  by abbreviation. `eos`, `fortigate` and `bigip` providers take an optional SSH `addr` and `host_key_fingerprint` for
  sessions. Console registration; migration 0425.
- Network devices (A270 part 2): `eos`, `fortigate` and `bigip` dynamic-secret providers rotate device account passwords
  (and the EOS enable password) through eAPI, the FortiOS REST API and iControl REST over HTTPS with the device's
  certificate pinned, single-phase with acknowledgement and rollback; discovery reads all three. Provider catalog
  47 -> 50 recipes.
- Network devices (A270 part 1): `iosxe` and `junos` dynamic-secret providers rotate local account passwords (and the
  IOS-XE enable secret) through the device's CLI over SSH, single-phase with acknowledgement, keeping each account's
  privilege level or login class and rolling an unproven change back; privileged account discovery reads both.
  Provider catalog 45 -> 47 recipes.
- Remote desktop (A269 part 2): access templates gain `desktop_clipboard` (deny, to_target, from_target, both); the
  reviewed policy reaches the gateway and its native helper loads the RDP clipboard channel only for an allowed
  direction (bounded, indexed by length). Sessions now return the approval they consumed when read back. Migration 0424,
  snapshot format 107.
- Remote desktop (A269 part 1): a viewer's clipboard is refused without ending the desktop session (its text is never
  forwarded and the refusal is indexed without content), and desktop recordings carry a searchable index
  (`GET /api/v1/access/sessions/{id}/recording/index?q=`, `trstctl access sessions recording-index`). OpenAPI census
  787 -> 788, CLI 854 -> 855.
- Windows local administrator check-outs (A268): a vaulted local administrator account registered as a `windows_local`
  access target (its native `windows` provider and account secret) is checked out through A261 — reviewed, revealed
  once, never opened as a session — and checking it in, or its deadline, queues its in-place native rotation, which an
  offline host runs when it returns. Migration 0423 admits the target type.
- The Change sets template selector truncates its closed label within the field in WebKit,
  keeping mobile pages within their viewport while retaining every full option name.

- Automatic access approvals can match exact target/folder scope, authenticated roles, a local
  time window, a whole-reason ticket pattern and a maximum lifetime. Rules record a policy vote
  and matched facts; nonmatches keep human review. Console review, revisioned API and CLI edits
  apply prospectively. Durable evaluations preserve one decision and the original expiry across
  retries and rule edits; emergency-session access never uses automatic approval.

- Account folders apply one access template to every registered target's session requests and
  check-outs. Requests cannot select another template, and changed policy revisions require a new
  review. Templates can require recording, refusing direct sessions and credential check-outs.
  The console manages folders, membership and recording rules; CLI `access folders` and
  `access targets folder` use the same tenant-scoped, event-sourced API.

- Access gateway, PostgreSQL (A254 part 1): a PAM PostgreSQL target can be bound to a gateway-role agent
  (`gateway_agent_id`, `gateway_address`); a session to it returns a one-time ticket and the gateway's identity,
  never the credential. The gateway (`trstctl-agent --access-gateway-listen`, new `gateway` role) claims the
  session as an agent job, redeems its login into locked memory, admits only connections carrying the ticket,
  and signs in upstream itself; `trstctl-cli access sessions connect` tunnels a stock client to it over TLS
  verified against the agent CA for the gateway's host and its SPIFFE ID (the agent CA signs a gateway's
  serving certificate only for hosts its own target bindings declare). Revoking the session recalls its job, so
  the gateway ends its connections. The gateway's PostgreSQL sign-in is its own (`internal/crypto/pgsignin`:
  SCRAM-SHA-256, MD5 or cleartext as the target demands, TLS always verified), so the agent binary links no
  database driver. Design and threat model: `docs/design/access-gateway.md`.
- Access gateway, SSH (A254 part 2; A254 is served): an SSH target bound to a gateway pins the host keys it
  accepts (`host_key_fingerprints`). The gateway generates each session's key in locked memory and the tenant
  SSH CA certifies it for the job the gateway holds (`SignJobSSHKey`: key ID `pam:<session>`, the session's
  principal, ending at its deadline, terminal only); stock `ssh` with no key reaches the target through
  `trstctl-cli access sessions connect`, which writes the gateway's host key to a known_hosts file. Shell, exec
  and SFTP are relayed; forwarding is refused. Revoking the session puts its key ID on the served KRL.
- Session recordings (A255 part 1): with an object store, tenant sealing and the audit signing key, the gateway
  records every session — SSH bytes and requests, SFTP as operations without file contents, PostgreSQL statements
  with bounded results — masking the session's credential and well-known token shapes before anything leaves it.
  Chunks upload in order with backpressure (`UploadSessionRecording`), are sealed for the tenant into the object
  store and chained, and the recording closes with a manifest signed by the audit key;
  `GET /api/v1/access/sessions/{id}/recording` and `.../recording/verify` read and check it.
- Recording access, live termination and retention (A255 is served): `recordings:read` plays recordings back and
  watches live sessions (`.../recording/frames?wait=`, `trstctl access sessions watch`), `recordings:export` exports a
  recording with its signed manifest and places legal holds, and every read is recorded. `access:terminate` ends a live
  gateway session; the gateway's end report acknowledges it, and until then the session reads `uncertain_until` its
  native deadline. `pam.recording_retention` deletes sealed recordings unless a legal hold keeps them.
- Redis sessions through the access gateway (A256 part 1): a `pam.database_targets` entry or tenant registration of
  `target_type: "redis"` names a Redis dynamic-secret provider and a gateway, which is required. The gateway redeems
  the session's own ACL user, signs in with AUTH itself (`internal/crypto/redissignin`; `rediss://` verified against
  the system roots) and relays a stock client's RESP commands; AUTH, HELLO with AUTH and RESET are never forwarded
  (a command the server refuses goes in their place, so the refusal arrives in order and the connection keeps the
  session's user). Recordings hold each command and each reply's type with bounded, masked values; a refused
  command is recorded by name only. `trstctl-cli access sessions connect` prints the `redis-cli` command. Migration
  0392 admits Redis targets; PostgreSQL targets' approval digests are unchanged.
- MySQL sessions through the access gateway (A256 part 2): `target_type: "mysql"` names a MySQL dynamic-secret provider
  and a gateway. The gateway answers a stock client's handshake itself (no TLS, any password), signs in upstream as the
  session's account with the client's capability flags (`internal/crypto/mysqlsignin`: caching_sha2_password fast
  path or full authentication to the server's RSA key, mysql_native_password on an auth switch), and refuses
  COM_CHANGE_USER. Recordings hold statements, column names, the first rows of each result, OK counts and error codes,
  bounded and masked. `trstctl-cli access sessions connect` prints the `mysql` command; migration 0393 admits MySQL
  targets.
- MongoDB sessions through the access gateway (A256 part 3): `target_type: "mongodb"` names a MongoDB dynamic-secret
  provider and a gateway. The gateway signs in as the session's user with SCRAM-SHA-256 (`internal/crypto/mongosignin`,
  with the SCRAM client now shared with the PostgreSQL sign-in in `internal/crypto/scram`), refuses a client's own
  sign-in (saslStart, saslContinue, authenticate, logout) with Unauthorized, removes a handshake's
  speculativeAuthenticate and compression offer, and records commands and replies, bounded and masked.
  `trstctl-cli access sessions connect` prints the `mongosh` command; migration 0394 admits MongoDB targets.
- ClickHouse sessions through the access gateway (A256 part 4): `target_type: "clickhouse"` names a ClickHouse
  dynamic-secret provider and a gateway; the session's job names the provider's endpoint (`upstream_url`). The gateway
  serves ClickHouse's HTTP interface, removes every credential a client sends (basic auth, X-ClickHouse-User/Key,
  certificate-auth headers, user/password parameters) and signs each request in as the session's user; requests and
  responses are recorded with bounded, masked bodies that stream. `trstctl-cli access sessions connect` prints the curl
  command; migration 0395 admits ClickHouse targets.
- Kubernetes sessions through the access gateway (A256 part 5; A256 is served): `pam.kubernetes_targets` (or a tenant
  registration of `target_type: "kubernetes"`) names a Kubernetes dynamic-secret provider and a gateway; the session's
  job names the API server, its CA and server name. The gateway adds the session's TokenRequest token to every request,
  removes a client's own credential and impersonation headers, relays exec/attach/port-forward upgrades, and records
  API calls plus remote-command streams (stdin, stdout, stderr; masked). `trstctl-cli access sessions connect` writes a
  kubeconfig naming the tunnel and no user; migration 0396 admits Kubernetes targets. SQL Server moves to the x86
  block; Oracle sessions are recorded as what comes next.
- Agent launcher (A257): an access bundle names the privileged accounts its runs may reach (`access_targets`; a run
  is refused any other with 403), and the new `access:sessions.open` permission (request, open and revoke one's own
  sessions; `access:write` includes it) is what a bundle carries for it. `trstctl-cli access agent --account
  TYPE/ID:ROLE ... -- <command>` requests and opens each account's session through its gateway after its reviews,
  serves the tunnels from its own process and runs the command with instructions (`TRSTCTL_ACCESS_INSTRUCTIONS`,
  `TRSTCTL_ACCESS_<n>_ADDR`, `PGHOST`/`PGPORT`, ...) and no credential: every `TRSTCTL_*TOKEN*` variable is removed
  from its environment and the gateway signs in. Its sessions are revoked when it exits. An unattended run minted for
  an agent's ID acts as the agent, and revoking the agent's broker identity (Q4) now also revokes those runs and ends
  every live session the agent opened; the response lists them (`BrokerAgentIdentityRevokeResult`). Migration 0397
  adds `access_bundles.access_targets`. `access sessions connect` now prints a `psql` line for PostgreSQL sessions.
- Credential health, access templates and emergency access (A258; A258 is served): every provider-backed PAM target's
  stored credential is signed in with once per `pam.health_check_interval` (default an hour, spread by target name),
  read-only, and its health (healthy, rejected, expired, locked, unreachable, error) shows on the target; a credential the
  server refused is not tried again until it changes or an operator runs `access targets health-check`, so no check adds
  a second failed sign-in. Access templates (`/api/v1/access/templates`) set a request's reason, its approvals (never
  below the deployment's) and its maximum length. Named emergency responders (`/api/v1/access/emergency/responders`) open
  a session at once (`POST /api/v1/access/emergency-sessions`, an hour at most); every approver is notified on the
  approval channels and the grant's post-incident review stays pending until someone else with `access:approve` records
  it. Migration 0398 (credential health, templates, responders, emergency grants), snapshot format 90, OpenAPI census
  719 -> 730, CLI census 786 -> 797.
- Browser sessions, part 1 (A259): a session opened with `"browser": true` leaves its ticket with the control plane
  (locked memory, bound to its opener, until its deadline) and the reply carries none. For an SSH session the control plane
  opens a shell through the session's gateway (`POST /api/v1/access/sessions/{id}/terminals`; output by long-poll, typed
  input in idempotent batches, resize, close), and the console shows it in a terminal (xterm.js, loaded on demand, with
  screen-reader mode) from Request privileged session → "Open in the browser". The gateway still signs in, records and
  masks. OpenAPI census 730 -> 735.
- Browser sessions, part 2 (A259): a PostgreSQL session opened for the browser gets a database console (`POST
  /api/v1/access/sessions/{id}/queries`, idempotent; the last result's columns and at most 1,000 rows, or the database's
  refusal with its SQLSTATE) run by the control plane through the session's gateway, which signs in, records and masks.
  The console's "Open in the browser" now covers both target types; "Open database console" shows the SQL console.
  OpenAPI census 735 -> 736.
- Brokered-account lifecycle, part 1 (A261): a PostgreSQL or MySQL PAM target registered with `account_secret` is
  vaulted — its sessions go through its gateway signed in as the account that application secret holds (read when the
  gateway claims the session), so nobody receives the credential and nothing is minted per session. The secret is an
  A240 static credential its provider rotates; a rotation schedule rotates it, and sessions opened afterwards sign in
  with the new credential while the old one is refused. Migration 0401 (`pam_targets.account_secret`).
- Brokered-account lifecycle, part 2 (A261): check-outs of vaulted accounts. `POST /api/v1/access/checkouts` requests
  independent review; once approved its requester reveals the account's current credential once
  (`/api/v1/access/checkouts/{request_id}/reveal`, audited as `pam.checkout.revealed`, a second reveal refused);
  checking it in (`.../checkin`) or its deadline queues the static rotation that retires the revealed credential. The
  console's access page gains a check-out panel. Migration 0402 (`pam_checkouts`), snapshot format 93, OpenAPI census
  747 -> 752, CLI census 814 -> 819 (`access checkouts request|reveal|checkin|list|get`).
- Privileged account discovery, part 2 (A260 served): Active Directory users through the LDAP provider (transitive
  members of the groups that administer the domain, protected users); staged accounts are imported into a folder only
  after independent review (`/api/v1/access/discovery/imports`, applied with the approval; refused when an account
  changed since its review) and importing grants nothing; a staged account can be dismissed with a reason
  (`/api/v1/access/discovery/accounts/{id}/dismiss`); `GET /api/v1/access/accounts` lists imported accounts. The
  console's access page gains a discovery panel. Migration 0400, snapshot format 92, OpenAPI census 743 -> 747, CLI
  census 810 -> 814 (`access discovery import request|apply`, `access discovery dismiss`, `access accounts`).
- Privileged account discovery, part 1 (A260): a dynamic-secret provider becomes a discovery source
  (`/api/v1/access/discovery/sources`, on demand or every hour or more); a scan reads its target read-only through the
  provider's administrator connection and stages the privileged PostgreSQL roles, MySQL accounts, SQL Server logins or
  Linux/Unix local accounts (with sudo rights and authorized keys' fingerprints), each with what makes it privileged,
  and records what changed since the previous scan (`/api/v1/access/discovery/runs`, `/accounts`). Discovery grants
  nothing. Migration 0399, snapshot format 91, OpenAPI census 736 -> 743, CLI census 803 -> 810 (`access discovery
  sources list|save|delete`, `scan`, `runs list|get`, `accounts`).
- Browser sessions, part 3 (A259 served): a Kubernetes session opened for the browser gets a terminal in a pod. The
  terminal request names a namespace, a pod and optionally a container and command (default `sh`); the control plane
  opens the exec through the session's gateway (WebSocket `v5.channel.k8s.io`), which adds the session's own token, so
  the service account's role bounds it and the token never leaves the gateway. The exec's exit status ends the terminal,
  and the gateway records the stream. The console's session form offers Kubernetes, and a pod form opens the terminal.
- Cloud KMS keys and load-balancer TLS policies (X4): a `cloud_kms_key` discovery source with the `aws-kms` provider
  lists every key in a Region through the read-only `ListKeys`, `DescribeKey` and `GetKeyRotationStatus` calls, with
  its type and size from the key spec, usage, state, manager, origin and automatic-rotation status (`enabled`,
  `disabled`, `not_supported` for keys KMS cannot rotate, `unknown` with KMS's error code), and flags a key KMS could
  rotate but is not rotating; key material is never read (proven against LocalStack KMS). A `load_balancer_tls`
  source reads the TLS policy each AWS Application or Network Load Balancer listener (`aws-elbv2`) or F5 BIG-IP
  virtual server (`f5-bigip`, iControl REST as a read-only user) enforces, and records one crypto-inventory finding
  per listener at the oldest version it allows, so a listener that allows TLS 1.0 is one weak TLSv1.0 finding,
  replaced when the policy is tightened (proven against ELBv2 and BIG-IP stand-ins).
- Live discovery of cloud access keys (M3): a `cloud_access_key` discovery source with the `aws-iam` provider
  lists every IAM user's access keys with status, creation date, age and last use (date, service, Region) through
  the read-only `ListUsers`, `ListAccessKeys` and `GetAccessKeyLastUsed` calls, flags an active key unused for
  90 days as stale (risk 80), and shows the keys in the NHI inventory as API keys; no secret access key is ever
  read, and the air-gap guard confines the calls. Proven against LocalStack IAM.
- Live checks for leaked secrets (P14 is served): with `secrets.validity_checks.enabled`, a scan checks each AWS
  access key pair it finds where it found it (an STS GetCallerIdentity signed with the pair, so the secret never leaves
  the host) and records the finding's `validity`; each check's endpoint must be declared in the checks' outbound
  allowlist and a per-provider rate bounds them. A secret found in a collected Slack channel names its poster and the
  tenant owner with the poster's email.
- ServiceNow two-way sync (P13 is served): a ServiceNow change request approved or rejected decides the trstctl
  request intake opened from it, once (relay job `ticket.status`); `POST /api/v1/incidents/executions/{id}/close`
  (`trstctl incidents executions close|closure`) closes a trstctl incident and resolves the ServiceNow incident its
  response dispatch opened (correlation `trstctl:incident:<id>`), and a replayed update changes nothing.
- Factory provisioning for devices (P12 is served): factory batches (`POST /api/v1/edge/factory-batches`,
  `trstctl edge factory-batches create|list|show|manifest|reconcile`) give a production-line station a quota of birth
  certificates under one edge delegation. `trstctl-agent --factory-issue` certifies each device's own CSR offline with
  no listener and refuses past the quota; the journal reconciles when the station reconnects, recording any birth
  certificate past the quota as over-production. Devices enroll on first boot and renew over EST at
  `/.well-known/est/factory` with a proof signed by their birth or operational key, through the relay enrollment proxy.
- ACME revocation of a certificate trstctl doesn't hold (N10 is served): a Certificate Transparency finding can be
  revoked at an ACME external CA. trstctl reads the certificate back from the log that recorded it, checks it against
  the finding, gets its own ACME account authorized for every DNS name in it through the issuer's DNS-01 provider,
  then asks the CA to revoke (RFC 8555 §7.6). **Revoke at issuer** now offers ACME CAs for CT findings.
- MDM device check-in behind approval (N9 is served): `POST /api/v1/mdm/{mdm}/devices/{id}/check-in/approval-requests`
  asks for one device trstctl has read from its MDM; after another reviewer approves, `POST .../check-ins` queues one
  job for the MDM schedule's relay, which calls Intune's `syncDevice` or sends a Jamf Pro blank push to that computer
  and records the MDM's answer (`GET /api/v1/mdm/{mdm}/check-ins`; `trstctl mdm check-in ask|run`,
  `trstctl mdm check-ins`). New relay kind `mdm.device.check_in`. The approval queue now also lists AD CS decision
  requests (N1), which reviewers could previously approve only by ID.
- A Slack app for approvals (N8): install per tenant through Slack's consent (bot token sealed under the tenant key),
  pick the approval channel, and approve or deny requests with buttons; members link their Slack users with a
  one-time code (`/trstctl link <code>`), and a press decides through the API's own approval route as that member.
  Every request from Slack is signature-checked (`trstctl integrations slack …`).
- Response playbooks for SOAR tools (N7): `clients/soar/` is a vendor-neutral pack of playbooks a SOAR runs as
  plain HTTP calls against trstctl's API — revoke a compromised certificate, rotate a leaked stored secret and
  resolve its finding, retire a triggered honeytoken — with idempotency keys built from their inputs and the
  exact API scopes their token needs, checked against the served OpenAPI document and run against the served API.
- Native leak-scan collection (N6): a third-party scan source with `collect` has trstctl read the content from
  the provider — an image from its registry over the OCI distribution API (every platform, config and layer
  files, digests checked; anonymous, bearer or token-service credentials), Slack channel history, Jira issues,
  GitHub Actions run logs and GitLab job logs — in the layout of the provider's export, so findings name the
  image, message, issue, or CI run or job; the content stays in a private temporary directory removed after the
  run.
- trstctl as the OpenID issuer clouds trust (N5): with `protocols.spiffe.oidc_issuer_url`, the token-exchange
  tenant has a published issuer `<base>/oidc/<tenant-id>` (discovery document and key set, the signer-held SPIFFE
  JWT key), exchanged tokens carry it as `iss`, and AWS (AssumeRoleWithWebIdentity), Google (workload identity
  federation) and Azure (federated credentials) can trust them with no cloud key on the workload;
  `GET /api/v1/workloads/oidc-issuer` (`trstctl workloads oidc-issuer`) shows what to register.
- AWS decoy keys are also looked for in a CloudTrail trail's log files (N4): an account attachment may name
  its trail (`trail`: bucket, Region, key prefix, organization ID, accounts), and the leader reads the trail's
  log files from S3 — every account of an organization trail, and data events when the trail logs them, which
  LookupEvents never returns. Each file is recorded once; each decoy use shows the calling and logging
  accounts, `event_category` and `found_in`; the account catalog shows what the trail read. Proven against
  LocalStack S3 with files in CloudTrail's layout.
- Secrets: an AWS STS provider with `revoke_with_deny_policy` ends a revoked lease's
  session before it expires through an inline policy on its role that denies that one
  session (`aws:userid`), read back before the revocation completes; denials of expired
  sessions are pruned, the provider catalog reports `deny_policy`, and leases show
  `revocation_method` (`deny_policy` or `native_expiry`). Proven against LocalStack;
  AWS's enforcement of the denial is a live proof (N3).
- Renewal waves for the switching kit (A265 is served): `POST /api/v1/switching/imports/{id}/waves/preview`
  assigns imported rows to deployment targets and names every row it leaves out and why, plus the fingerprints
  the other product must stop renewing; `POST .../waves` issues each row's single trstctl identity through the
  ordinary issuance policy so trstctl renews it from then on; `POST /api/v1/switching/waves/{id}/rollback`
  (refused while an issuance or renewal is in flight) withdraws queued deploys, pauses the renewals and returns the
  rows to watch-only. The endpoint watch flags a wave row the other product renewed (`trstctl switching waves`).
- MCP client configuration discovery on hosts (P7 host detectors are served): `trstctl-agent
  --inventory-mcp-config-roots` reads MCP client configuration files by format and reports each configured MCP
  server — transport, program or host, and which fields hold a static credential, never a value — as `mcp_server`
  findings in discovery and the shadow NHI posture; an unchanged rescan sends nothing and writes no event.
- The switching kit, parts one and two (A265): `POST /api/v1/switching/imports/preview` maps another
  certificate-management product's export (CSV or JSON, described by format, with a column map for its own
  column names) without changing state, giving every row one outcome — mapped, mapped with named gaps,
  duplicate, unparseable or expired — with folder profile proposals, owners per application group, the rows
  already in the inventory and a digest; `POST /api/v1/switching/imports` applies exactly that digest, and the
  leader records the certificates (watch-only, never renewal candidates) and owners in bounded batches,
  linking certificates already in the inventory instead of rewriting them. `POST
  /api/v1/switching/imports/{id}/watch` matches every imported certificate to what its endpoints serve, under
  the control plane's egress rules with private ranges only by explicit grant, flagging serves_other,
  unreachable and no_endpoint, and repeats daily (`trstctl switching import|imports`).
- AD CS approve and deny through the relay, behind approval (N1 is served): a request an AD CS template holds for a
  CA manager is approved (`certutil -resubmit`) or denied at the CA by the issuer's domain-joined relay only after
  another reviewer approves the exact decision, and only while the CA still holds it as pending; `GET
  /api/v1/external-cas/{id}/adcs-decisions` shows each decision queued, decided with the CA's disposition, or failed
  with the relay's reason.
- Azure Key Vault disable, labeled not revoked (N2 is served): `POST /api/v1/certificates/{id}/key-vault-disable`
  disables the exact Key Vault certificate version the inventory found, through a `write_token_ref` configured
  beside the vault's discovery source, from an outbox job with readback; every answer says it is not a revocation
  and the inventory row keeps its status.
- The edition and qualification ledger (A253 is served): `go run ./tools/editionledger` generates
  `docs/editions-ledger.md` and `.json` from the license table and the feature map; the README and
  `docs/editions.md` carry its generated blocks, the Editions API and the console name the no-license
  edition Free as the ledger does, and guards fail on drift, on another name for it, and on a page that
  misstates the core's source-available license.
- Evidence report templates (A252 is served): five scheduled report types — lifecycle, access, rotation,
  incident response and qualification evidence — replay one window of the tenant's event log, sign like
  every scheduled report and verify offline. Each counts its sections' events by type, tallies outcomes,
  names up to 25 opaque subject IDs per section, reads the current state as counts, and says what it could
  not observe; no event body, certificate, secret, token or name is carried. `GET
  /api/v1/reports/evidence/{kind}` (`trstctl reports evidence`) renders one unsigned for review.
- The console's **Agent access** page (A251 is served): bundles, grants with the effective
  authority after every change, authority lookup with delegation chains and bounds, a run for
  yourself with its token shown once and launch lines, runs with revoke, and activity search and
  export.
- Agent access activity and the run launcher (A251, second part): `GET /api/v1/access/activity`
  (`trstctl access activity`) searches bundle, grant and run changes and each run token's
  recorded uses, newest first, by bundle, principal or text; `GET /api/v1/access/activity/export`
  returns the matching rows as one metadata-only JSON document (no token, token hash,
  Authorization value or request body). `trstctl access run --bundle <name> -- <command>` mints a
  run under your own grants, gives the command its token as `TRSTCTL_TOKEN` (never your own), and
  revokes the run when the command exits.
- Agent access bundles (A251, first part): `POST /api/v1/access/bundles` saves a reusable set of
  permissions for custom agents, CI jobs and private MCP servers; a grant gives it to a user or
  a machine; `POST /api/v1/access/runs` (the new `access:bundle.run` permission) mints a run's
  short-lived credential under the caller's own live grants, returned once with launch lines.
  A run's authority is derived again from its grants at every request: removing one of several
  grants leaves exactly what the others give, and deleting a bundle, offboarding a member or
  revoking the run stops it on the next request. Grant changes return the principal's effective
  authority; `GET /api/v1/access/authority` adds active runs, delegation chains and the
  revocation and outage bounds. Nobody hands an agent more than they hold, and a bundle never
  carries authority over access.
- Package readiness, third part (A250 is served): a registry directory holds several versions
  side by side (the Go `list`, the npm document's `latest`, the PyPI page and `maven-metadata.xml`),
  and `make sdk-install-check` now installs one version and upgrades each SDK to the next from the
  same registry, running the round trip on both. A tagged release attaches the four packages as
  `trstctl-sdk-registry_<version>.tar.gz` with SLSA provenance. A CI job checks the CLI and agent
  archives on clean Linux and macOS runners: checksums, unpack, run, and the commit `--version`
  reports.
- SDK packages from a local registry (A250, second part): `scripts/release/sdk-packages.sh`
  (`make sdk-packages`) builds the Go module, the npm tarball (now compiled JavaScript and
  declarations, so plain Node loads it), a pure-Python wheel and the Maven jar of one version with
  `manifest.json` and `SHA256SUMS`; `go run ./tools/sdkpack serve` serves them as a Go module
  proxy, an npm registry, a PEP 503 index and a Maven repository. `make sdk-install-check` (in CI)
  installs each by exact version in a clean environment and runs auth, read, rotate and revoke
  against a served control plane, with retries keeping their Idempotency-Key and waiting out
  `Retry-After`. The Java SDK's `PkiSecret` now carries the certificate ID.
- One SDK surface for secrets, PKI and revocation (A250, first part): the Go and TypeScript SDKs
  gain the secrets-store calls (create, get, rotate, delete) and PKI-secret issuance the Python
  and Java SDKs had, and all four gain certificate revocation (`RevokeCertificates`,
  `revokeCertificates`, `revoke_certificates`). The Go SDK takes and returns secret values as
  `[]byte` and wipes its own copies. Each SDK's tests show a retried mutation keeps its
  Idempotency-Key and waits out `Retry-After`.
- Unattended evaluation cycles (A249, third part; A249 is served): `trstctl evaluate --cycles n
  --interval d` repeats the chosen journeys with nobody watching, into one pack
  (`trstctl.evaluation-pack/v3`) that keeps every cycle. A cycle cut short because the control
  plane could not be reached is `interrupted`: the command waits up to `--recovery-timeout` for
  `/readyz` and records the outage, and the run passes only if the next cycle passes after it.
  After the first cycle the certificate journey issues the enrolled identity's next certificate
  through renewal. The incident journey runs once.
- Incident journey for `trstctl evaluate` (A249, second part): `--journeys certificate,incident`
  responds to a compromise of the key behind the certificate the certificate journey deployed —
  the effect-free compromise preview, a revoked-credential game day (static preview and mocked
  rehearsal), the reviewed command that revokes it at the CA and has the host agent stop the
  listener, then OCSP and this machine's handshake to check both. `--force-failure incident`
  reports the last check as a failure.
- Workload identity journey for `trstctl evaluate` (A249, second part): `--journeys workload`
  dials the Workload API socket (`--workload-socket` or `$SPIFFE_ENDPOINT_SOCKET`) as a workload,
  checks the X.509-SVID it is handed against the trust bundle (one SPIFFE ID, the key is the
  SVID's), verifies a JWT-SVID for a run-unique audience offline against the JWT bundle, and
  requires the socket to validate the token for that audience and refuse it for another.
  `--force-failure workload` reports that last check as a failure. The pack keeps the SPIFFE ID
  and the token's digest only.
- Reviewed change sets in the console (A248, third part): the **Change sets** page under Govern &
  administer writes the same typed set as the API and GitOps — from a template (onboard an
  application, grant a member roles, add a connector target), the form or JSON — plans it,
  shows the per-object plan, and applies only the reviewed plan digest. An edit after planning
  marks the plan stale, and a `409` asks for a new plan. With a model configured, the page drafts
  a set with AI and plans it the same way.
- Evaluation across journeys (A249, first part): `trstctl evaluate --journeys
  certificate,secrets,ssh` adds a secrets journey (create, read back by digest, rotate,
  `trstctl run` into a child process that checks the value without printing it, delete and
  read 404) and an SSH journey (issue a user certificate for a generated key, verify it
  offline against `/ssh/ca`, revoke it, find its serial in `/ssh/krl`) to the same signed
  pack, format `trstctl.evaluation-pack/v2` when more than the certificate journey runs.
  `--force-failure <journey>` makes one step expect what did not happen, so the pack shows
  that failure as one. `--deployment-target` is now needed only for the certificate journey.
- AI drafts of reviewed change sets (A248, second part): `POST /api/v1/changes/draft` (CLI
  `changes draft`) turns a request in words into a typed change set with the configured model and
  plans it like any other, never applying it. The model gets the tenant's names only — no specs,
  configs, chains, emails or member subjects — a request holding a key, token or password is
  refused before the model call, and each draft records `ai.change_set.drafted` (digests, never
  the request). Without a model it answers 503 and nothing else changes. Fixed: an owner without
  an escalation chain now reads back as planned (its stored null chain is the empty chain).
- Reviewed configuration change sets (A248, first part): one typed set of certificate profiles,
  CA bindings, connector targets, member role grants and owners, written as JSON or YAML.
  `POST /api/v1/changes/plan` (CLI `changes plan -f`) refuses a malformed or over-broad set, one
  carrying a secret value, and one beyond its author's permissions (`changes:write` plus each
  object's own permission; member grants get the members API's checks), then lists per object
  the identities, credentials, grants, destinations, approvals, events and verification
  involved. `POST /api/v1/changes/apply` (CLI `changes apply -f <set> <plan_digest>`) needs the
  reviewed plan digest, refuses a plan the tenant has moved past, writes each object through
  the operator's own command and reads it back. New permission `changes:write`.
- Rehearsals of failure scenarios (A247): save a scenario — approval resumption,
  target outage, renewal failure, revoked credential, stale policy, restore or retry — with its
  candidate, data set (named identities, or a scrubbed failure: identifiers and codes, no values)
  and the effect each step should have (`POST /api/v1/rehearsals/scenarios`, CLI `rehearsals
  scenarios save`; revise with `PUT`). A run (`rehearsals run`, permission `incidents:game-day`)
  replays it as a static preview against the configuration, a mocked rehearsal of the
  documented behavior, a sandbox execution against a non-production target (a retry runs the
  target's dry-run test twice through the idempotency layer) or a live observation of
  production's records (a restore reads the newest signed drill attestation), and records the
  tool and connector versions, the candidate, the data set's digest, the expected effects and
  what it observed. Its label is its mode's: a mocked success reads `mocked: matched`, never
  live. A sandbox replay reads environments from the target and owner records and refuses
  production ones and data sets that name stored secrets; a step a mode cannot run yet blocks
  the run.
- Operations dashboard, upgrade preflight and rollback (A246): **Deployment health** (`GET
  /api/v1/operations/dashboard`, CLI `operations dashboard`) shows backup freshness, restore
  proof, queue lag, signer readiness, data freshness and dependency health with the numbers
  behind each state. `trstctl --upgrade-preflight` reads what a binary would apply to the
  database, what blocks it and how the upgrade is rolled back, changing nothing; it exits 1 when
  blocked. A failed migration leaves the ones before it applied and itself rolled back, and a
  failed concurrent index build drops its invalid index, so the previous binary runs and the
  fixed one continues. The restore drill reads the restored events, CA keys and stored secrets
  back against the backup, and its signed attestation carries the counts. Install and failover
  runbooks join the upgrade and disaster-recovery runbooks.

### Fixed

- A push to a branch other than the default one now scans that branch (OD-3): the repository scan cloned the default
  branch and then could not check out the pushed commit. A ref or commit that git could read as an option is refused
  before it reaches git's command line.
- The Security scans retry a container registry error. The Trivy job builds the runtime image
  before scanning it, and Docker Hub answered 500 to the build on 2026-11-12, so the job failed
  without scanning anything. Its registry operations (the base image lookup and the build) now run
  through `scripts/ci/retry-registry-errors.sh`: an HTTP 429 or 5xx answer or a network timeout is
  retried up to four runs in all, 20, 40 and 60 seconds apart; any other failure is not retried.
- A Windows host agent's rotation report is accepted with the outcome the agent sends
  (A268-O1). The agent reports a proved local-account rotation as verified and any other result
  as failed, but the control plane accepted only an executed outcome, so a rotation the host
  proved never completed and a failed or uncertain result never reached the rotation. A
  delivery the host reported uncertain or never applied is no longer re-sent by the queue.
- A dependent AD rotation whose review expires during its final checks no longer strands the account
  (A267-O3). The worker checked the deadline before the last preflights and the full read of the
  reviewed scope, then stamped the reset's start later. A read that outlasted the deadline produced a
  start the read model refused while the event log kept it, so later recovery could not proceed. The
  start is now stamped once, after those checks, and that same instant must be inside the review;
  otherwise the rotation takes the deadline's path without resetting the directory.
- Privileged account discovery's actors are covered by privacy (A267-O2). Who saved a source,
  requested a scan, dismissed an account or imported one was kept in the discovery read models
  outside the subject export, erasure and retention, so an erased person still showed in the scan
  readback. They are now exported, an erasure replaces them with the placeholder and clears the
  free-form dismissal and import reasons, and retention keeps a finished scan's requester as a
  digest.
- A managed-key mutation whose short synchronous wait ran out during a read returns its `202`
  receipt (A261-O1). The command was already durable, but a read that failed because the wait's
  own time ran out (a driver reporting it as cancellation, or the completed key's read crossing it)
  returned an error instead of the pollable operation the wait's timer returns. A read that fails
  before the wait's time runs out, and the caller's own cancellation, are still errors.
- The Provider certificate cap counts current certificates (MTR-D1). The certificate meter the cap and
  the usage evidence read, `certificates_stored`, counted every certificate not revoked: a renewal
  keeps its predecessor as superseded, so the count grew by one per renewal (about eight a year per
  endpoint on 47-day certificates), and expired certificates counted too. A tenant whose renewals
  filled its tier was refused a genuinely new certificate (429) while renewals kept passing. A new
  `certificates_current` gauge counts active, unexpired certificates; it is the certificate line in
  signed usage evidence (saying why it has no independent recount) and what `max_certificates_stored`
  caps, and the issuance gate consults it. `certificates_stored` and `certificates_issued` stay as
  telemetry, and the console's evidence table and quota form say so.
- Every device provider's scan says why it could not sign in (DEV-D1). A privileged-account scan
  records a failure class (rejected, expired, locked, unreachable or error) so an operator knows
  whether to fix the stored administrator credential or the network; after the `esxi` fix (A271-D1),
  `redfish`, `vcenter-sso`, `iosxe`, `junos`, `eos`, `fortigate` and `bigip` still read a refused
  sign-in, and a refused connection, as `error`. Each now reads its device's refusal (a 401 session
  or sign-in, a refused FortiOS API token or `/logincheck`, vCenter `dir-cli`'s LDAP error 49, an SSH
  host refusing every credential after proving its pinned key) as `rejected`, and a device that does
  not answer as `unreachable`.
- A backup set covers the PAM recording chunks waiting for the object store (found A278-D1). A278's
  staged recording chunks (`pam_recording_uploads`), each written with its outbox entry until the
  outbox worker stores it, were in no backup class, so a restore dropped chunks that were still on
  their way while restoring their outbox entries. They are now recovered from the PostgreSQL dump
  with the outbox and restored beside it.
- The upgrade preflight counts a migration destructive by what its statements do (A246-L2). It
  matched a word list anywhere in a migration's text, so 0160, which only empties the disposable
  read-model snapshots, read as destructive and the preflight demanded a fresh backup before it,
  and a keyword in a block comment or a string counted too. Statements are now read one by one with
  comments and quoted text left out; removing rows only from tables the event log rebuilds (read
  models and their snapshots, not the preserved attestations, never with `CASCADE`) is not
  destructive, and dropping, renaming, retyping, `SET NOT NULL` or removing any other rows still is.
  Of the shipped migrations only 0160 changes class.
- A secret an environment promotion creates takes its source's owner (A236-L2). Promoting dev into
  stage created each missing stage secret with no owner, so the project view showed it as unknown and
  the owner's application view left it out. The plan now names the owner each created secret takes
  from its source (`owner_id`, `owner_name`, bound by the plan digest), the console's plan shows it,
  and the batch writes it; a source with no owner gives none, and an update keeps the target's own.
- Reading what a dynamic-secret lease reaches records an event only when it changes (G2-L3). The
  leader reads each active lease's access every six hours, and every read appended a
  `dynsecret.lease.access_observed` event even when nothing had changed: 40,000 events a day at
  10,000 leases. A read that finds the access as recorded now only stamps it; the observation is
  recorded when it changes and once a day as a heartbeat, and an unknown read that stays unknown is
  not recorded again. The access graph's lease shows `access_checked_at` (the latest read) and
  `access_recorded_at`.
- A Slack approval request is posted once when the answer to its post is lost (N8-L1). Slack has
  no idempotent post, so when Slack kept a message but the connection dropped (or trstctl stopped)
  before trstctl recorded it, the outbox delivered the post again and the request appeared twice.
  Each post now carries its request in Slack's message metadata, and before posting trstctl looks
  through the approval channel's last day of messages for that request's earlier post and records
  it instead. The app asks for `channels:history` and `groups:history` for that; an install made
  earlier checks nothing until it is installed again, which `GET /api/v1/integrations/slack`
  (`duplicate_post_check`) and the console say. The console gains **Approvals → Approve from
  Slack**: the install, its channel and its check, install or install again through Slack's
  consent screen, the channel picker, a reviewer's link code, and uninstall.
- A decoy secret alerts once per reader for good (Q6-L1). A decoy raises one critical alert per
  distinct reader, but the alert's outbox row was the only record of who had read it, and the outbox
  sweep reclaims a delivered row a day after delivery, so the same reader reading again a day later
  alerted again. The decoy now keeps its readers, each as a tenant-bound one-way reference with its
  first and last read and its read count, and alerts only for a reader it has not seen; a rebuild
  reconstructs them from the reads and snapshots carry them. The decoy API (`readers`, `reads`,
  `last_read_at`) and the console's decoy list show how many readers read it, how many reads they
  made and when it was last read. A subject's export lists every decoy they read with their own
  reads, and an erasure moves their reader record to their placeholder.
- A private key found in a secret store is linked to its certificate (A172-L3). A stored PEM private key
  was fingerprinted by its text only, so nothing tied it to the certificate it belongs to. Its finding
  now also records `spki_sha256`, the SHA-256 of its public key (read behind the crypto boundary; none
  for an encrypted key), and the credential graph links the stored key to each inventory certificate
  with that public key through a new `KEY_OF` edge, which the console's graph views name.
- A decoy secret's value found by a secret scan is the known decoy, not a leak (Q6-L4). A decoy's value
  planted as a lure in a repository raised a high-risk leaked-credential finding, because the scanners
  report where a secret is, never what it is. Repository, third-party and on-demand scans now compare
  the lines around each finding with the tenant's live decoy values in memory, wipe both and keep
  nothing about the scanned value; a match carries `known_decoy` (the decoy's ID and label) at risk 10,
  and the console's discovery findings name it. The comparison raises no read alert, and a retired
  decoy's value is an ordinary leak again.
- A sign-in collection no longer flags trstctl's own health check before its record lands (A274-L1).
  trstctl records a credential health check when it finishes, after the check has signed in, so a
  `pam_signin` run that read the sign-in in between raised a compromised-credential finding for
  trstctl's own sign-in. A run now judges a dated sign-in only once it is older than the 30-second
  clock-skew allowance and reads back that much past its lookback, so the next run judges the ones it
  left: an outside sign-in is still flagged, one run later. A sign-in dated only when a run first saw
  it (a MySQL connection) is judged at once.
- A cloud-store migration member's gate waits for the load balancer (A166-L3). The gate closed as soon
  as the certificate store served the successor, while the provider's load balancers could still be
  serving the predecessor until the change propagated. When the target names the endpoint its load
  balancer answers on (`verify_address`, `verify_server_name`, and `verify_private_egress_cidrs` for a
  private range), the gate also needs a TLS handshake there to present the certificate: the member waits,
  rechecking every 30 seconds without spending retries, for up to 30 minutes from when its row was
  queued, and fails the gate after that. The same applies to a rollback's re-bind. The console's member
  evidence says what closes the gate.
- An MCP client configuration removed from a host is reported gone (P7-L2). The inventory kept a removed
  server's finding as if it were still configured, and a host whose last configuration was removed sent no
  report at all. Each report is the host's whole MCP inventory, so a server the newest report no longer
  lists now reads `removed_at` in the discovery findings, shows as removed from the host in the console,
  and leaves the open shadow NHI posture (counted under `removed`); a host with no configuration left
  sends one empty report, which only this source may send. A server configured again reads present.
- The workload JWT signing key rotates without breaking a cloud's cached key set (N5-L3). The key
  that signs exchanged tokens and JWT-SVIDs, published by the OpenID issuer, could not rotate at all.
  `POST /api/v1/workloads/jwt-keys/rotate` (`workloads jwt-keys rotate`, `issuers:write`) creates the
  next key in the signer and publishes it at once, signs with it after `publish_ahead_seconds`, and
  keeps the replaced key published for `retain_seconds` after the switch; `GET
  /api/v1/workloads/jwt-keys` (`workloads jwt-keys list`) shows each key's state and times, and the
  console's Workloads page shows the issuer and its keys and rotates them. The rotation is an event
  (`workload.jwt_key.rotated`, read model `workload_jwt_keys`, snapshot format 114).
- A scoped sync's failed delivery raises a warning (A237-L4). When the write or the delete of a
  destination key a scoped secret sync manages failed for good, only `scoped-syncs show` said so, and
  nobody was told. Each such failure now raises one warning on the notification surface
  (`secret.scoped_sync.delivery_failed` on `notification.secret_sync`), in the transaction that records
  it, naming the sync, the key, the target and the closed reason, never a value. A replay or a rebuild
  from the log raises no second alert.
- A report removal that keeps failing says why (A206-L1). When the report retention could not remove a
  report, the outbox recorded only `external_delivery_failed`, so an operator could not tell an
  archive that refused the delete from one that kept the report or could not be read without the
  logs. The removal's outbox row now keeps one of three closed classes (`report_removal_refused`,
  `report_removal_kept`, `report_removal_unconfirmed`), never the archive's own words, and the run's
  API answer carries `artifact_removal_failure` (reason, attempts, whether it still retries and when
  next), which the console's signed runs show.
- The report retention removes every version of a report (A206-L2). On a bucket that keeps versions
  (versioning is on whenever a bucket has S3 Object Lock), a plain delete only adds a delete marker:
  HEAD then answers 404 while the report's version stays in the bucket, and the run was recorded
  expired with the report still there. The retention now lists the report's versions, reads each
  one's Object Lock (a locked version keeps them all, and the run says until when), deletes the data
  and then the delete markers earlier deletes left, and records the run expired only when the bucket
  lists no version of the report. This needs `s3:ListBucketVersions` and `s3:DeleteObjectVersion` on
  the archive bucket; without them the removal retries and the run stays unexpired. A store that does
  not implement version listing is removed from as before.
- A decoy trail's older day folders are read (N4-L2). The organization trail reader read only today's
  and yesterday's day folders, so a log file delivered while the control plane was down for longer
  than a day was never read, and a decoy key used then was never found. It now reads every day folder
  from the day the oldest watched decoy was created (at most 90 days back) through today, oldest first;
  a folder of a day before yesterday is not listed again once read in full, files already read are
  skipped as before, and one pass lists at most 1,000 folders, leaving the rest for the next.
- A decoy login the watcher cannot read records a monitoring gap (Q6-L10). When a decoy's provider
  stayed unreachable, or its database was gone while its lease was active, the watcher only logged it
  every 30 seconds, so nobody learned that uses of the bait were not being seen. A decoy unread for
  five minutes now records a gap on the decoy (`watch_gap_since` and `watch_gap_reason` on the decoy
  login API), from `honeytoken.watch_gap.opened` and `.closed` events, with one warning alert through
  the outbox; reading it again closes the gap.
- A decoy login retires when its lease ends (Q6-L9). A database decoy lives as long as the lease
  that minted its login, but when the lease expired or was revoked the decoy stayed active: its
  database was gone, the watcher saw nothing to count and raised nothing, and the decoy kept reading as
  watching. Each check now reads the lease; once it has ended, a last check still raises the alert of
  a decoy the bait used, and an unused decoy retires. A decoy whose database is gone while its lease is
  active is reported by the watch instead of read as unused.
- A decoy login used in another database alerts (Q6-L8). A decoy PostgreSQL login has CONNECT only
  on its own empty database, but PUBLIC keeps CONNECT on databases such as `postgres`, and a session
  the bait opened there counted nowhere the watcher looked. The watcher now also reads the role's live
  sessions in every other database and raises the decoy's alert, naming that database; a session that
  opens and closes between two checks there is still not seen.
- Erasing a subject clears them from decoy alerts (Q6-L3). A decoy secret keeps its first reader, and
  each reader's alert in the outbox names them until the delivered row is swept a day later (and a
  waiting one, never). Subject erasure did not reach either, and a subject export did not list the
  decoys they read. The export now lists them, and an erasure pseudonymizes the decoy's first reader
  and replaces the subject in the text of their alerts, delivered or waiting, keeping other readers'
  alerts; the privacy data catalog lists decoy readers.
- Registering one secret as a decoy twice at once makes one decoy (Q6-L2). The register route checked
  that no live decoy watched the secret, then appended the new decoy's event; two registrations that
  arrived together could both pass the check and both create a decoy. The check, the append and its
  projection now run under the projection lock, so the second sees the first's decoy and is refused
  (409); sixteen concurrent registrations make exactly one.
- A misuse alert is no longer lost when its transaction fails (M2-L4). Misuse detection appends a
  finding's event, then projects it and enqueues its alert in one tenant transaction; when that
  transaction failed after the append, the event tail projected the finding later but nothing wrote
  its alert. Each detection pass now writes the alert of an alerting finding that has none, rebuilt
  from the finding's own event and keyed like the original, for findings up to six hours old, well
  inside the day a delivered alert row is kept, so no alert is written twice.
- A host agent's Workload API can issue workload identities: `protocols.spiffe.entries` binds a
  workload's SPIFFE ID to the selectors a named host agent must observe (B8-D1). Entries a host
  agent may deliver must name that agent, and nothing could, so every workload that dialed an
  agent's `--workload-api-socket` was refused. Each entry is scoped to the agent's own
  certificate identity; malformed entries are refused at start.
- A Redfish controller that answers a new session with any success carrying `X-Auth-Token` opens
  a session (A271-D2). The `redfish` provider accepted only `201 Created`, as DSP0266 has a service
  answer; DMTF's reference client accepts any success that carries the token, and DMTF's reference
  mockup server answers `204 No Content`, so the provider could not open a session there.
- An ESXi host's refused administrator sign-in reads `rejected`, and a host that does not answer
  `unreachable` (A271-D1). A privileged-account scan records why it failed as a class, so an
  operator knows whether to fix the stored password or the network; the `esxi` provider returned
  plain errors, so both read `error`. Found by proving the provider against stock vcsim.
- A dynamic-secret lease records who requested it (G1-L1). A lease kept only a non-reversible
  request binding, so the access graph showed it with `holder_recorded: false` and no holder, and
  a review generated from the graph could not say whose access it was. The lease now records the
  subject whose request opened it (migration 0437, from the pending event's actor): the lease read
  carries `requested_by`, the graph shows that person or principal holding the lease, and privacy
  export, erasure and retention cover the record (snapshot format 113). Leases from before name
  no requester.
- An access review's next review opens when it is due (Q1-L7). A keep decision recorded when its
  credential is next reviewed, and nothing acted on the date. The leader's review reconcile now
  opens a "Next review: <campaign>" campaign with the same reviewer, scope and time to decide, one
  pending item per due credential carrying its facts and a `next-review-of:` link to the item it
  reviews again; projecting it clears that item's pending date, so each opens once. A campaign a
  person starts cannot carry that link.
- An access review item whose credential trstctl no longer holds now closes (Q1-L3). A revoke
  decision's item closed only when its credential read revoked; a credential whose record was
  removed read as no evidence at all, so the item stayed open on every reconcile pass and a failed
  revoke of it was retried for a week. Gone is now evidence of its own: the item closes with
  `closed_as: gone` and evidence naming what is gone (an item closed on a revoked credential reads
  `closed_as: revoked`), and the console says "Closed: trstctl no longer holds this credential".
- Audit archive downloads are limited per caller as well as per tenant (A234-L3). One bucket per
  tenant, six a minute, let one caller holding `audit:archive.read` spend the tenant's budget and
  lock its other auditors out. Each caller now has six a minute, taken before the tenant's thirty,
  and the refusal says which limit applied.
- A ticket's requester can no longer approve their own issuance request under their login
  (A225-L1). The request recorded the requester as the ticket system names them (Jira's reporter
  by display name, a ServiceNow display value), the approver signs in under a login subject, and
  the separation-of-duties check compared the two strings exactly. The check now also refuses a
  decider whose tenant member record holds the requester's email or display name (ignoring case),
  the Jira reporter is read by the email Jira shares ahead of the display name, and the refusal is
  answered 403. A requester named by an identifier no member record holds cannot be told apart.
- A tenant baseline, and the Provider tenant template that applies one, may name a webhook at a
  private address, decided by the operator's grant for the tenant it is applied to (A223-L1). The
  baseline is validated before any tenant is known, and that validation refused every private
  literal, so a template could not carry one even for a granted tenant, and the apply step never
  consulted the tenant's grant. Validation without a tenant now accepts an address an operator
  could grant (RFC 1918 or unique-local; never loopback, link-local, CGNAT or a metadata address),
  and applying the baseline checks the tenant's own grant: without it that channel fails naming
  the grant and the rest of the baseline applies.
- In an AWS KMS account several tenants share, a tenant's reconcile round no longer reads the
  other tenants' managed keys as its drift (A168-L2). The `awskms` source asserted every key
  carrying trstctl's operation tag, so each tenant's witness evidence held the other tenants' key
  ids, specs and states. A key the signer creates now also records its tenant in the same
  CreateKey request (`trstctl-tenant`), and the source leaves out a key tagged as another
  tenant's, with or without `all_customer_keys`. Keys created before the tag carry none and are
  asserted as before.
- An AWS STS lease's session can't assume another role (N3-L3). A session chained from a lease
  runs as the other role, which neither `revoke_with_deny_policy`'s denial on the lease's role nor
  the lease's expiry reaches, so it outlived the lease's revocation by up to an hour. Each lease's
  `AssumeRole` now passes a session policy that keeps what the role allows and denies
  `sts:AssumeRole`. A provider whose workloads must chain sets `allow_role_chaining: true`: its
  leases are issued without the policy and read `role_chaining: true`, their revocation stays
  pending an hour past the session's expiry, and the setting is refused with
  `revoke_with_deny_policy`. Leases issued before this change could chain. The lease view says when
  a lease's sessions end by an hour past its session's own expiry.
- An issuance approval no longer outlives a change to what the identity puts into the certificate
  (A245-L5). An approval bound the identity's lifecycle version, which is 0 for every first
  issuance and never moves on an attribute edit, so an approval asked for one subject key could
  issue another: rebinding the same destination and CA with a post-quantum subject key algorithm
  left it standing. It now also binds a digest of the identity's kind, name, issuer, validity
  window and attributes (the requester's CSR, subject names, subject key algorithm, reviewed
  preview and the rest; not the owner, the renewal pause, or the destination and CA attributes
  bound on their own). A change supersedes the approval when it is decided or used, and the
  application view names "certificate details" as what changed; an ownership reassignment leaves
  it standing. The application view's profile is now the one issuance resolves (the identity's,
  the one retained from its first issuance, else the served default): reading the identity's
  attribute alone said every approval under the served default had a changed profile.
- A managed key generated in a PKCS#11 HSM can only sign (P9-L4). The key-pair template left the
  token's defaults for the other uses, so SoftHSM made the private key usable to decrypt and unwrap
  and the public key to encrypt and wrap. The template now sets those uses false, and a SoftHSM
  test reads each attribute back from the token.
- The SMTP relay password no longer lingers in memory after a send (P15-L5). net/smtp's client
  base64-encoded the PLAIN response into a command string and its writer's buffer, copies nothing
  could wipe. The email channel now drives the SMTP exchange itself (the same commands net/smtp
  sends) and writes the AUTH line from a buffer it wipes once written; after STARTTLS the line is
  sealed in place, and the relay password the ACME email challenge holds as bytes is never a string.
- Host discovery reads a PKCS#12 file's certificates without decrypting its private key (X2-L3).
  The library decoder decrypted the key on the way to the certificates and left its own copies of
  the decrypted key in memory. A certificate-only reader in `internal/crypto/pfx`, written from
  RFC 7292, 8018, 9579 and 2268, checks the file's MAC with the password, decrypts only the contents
  that hold certificates (PBES2/AES, legacy 3DES and RC2), notes a key bag without opening it, and
  orders the key's certificate first by `localKeyId`. It returns what the library decoder returns
  for every encoding the library and OpenSSL write, and it has a fuzz target.
- A secret file the agent renders on Windows no longer inherits its directory's readers (A238-L10).
  The mode set only the read-only attribute, so whoever the directory's access control list let read
  could read the secret. The file now gets an explicit, protected DACL from its mode before any
  content is written: the agent's user and SYSTEM, the agent's primary group for the group bits, and
  Authenticated Users for the other bits. CI's Windows job checks it.
- A custom role with `graph:read` but not `access:read` no longer reads the access side of the
  graph (G1-L2): tenant members' subjects and names, their roles, AI agents, and the API tokens,
  machine sessions, PAM sessions and leases they hold. Every graph route leaves it out for such a
  caller, `GET /api/v1/graph` carries `access_omitted`, and the Graph page says what is hidden and
  why. Built-in roles with `graph:read` also hold `access:read` and see the whole graph as before.
- A Linux workload's `unix:path:` selector can no longer be taken from a reused pid (A203-L3). The
  host agent read `/proc/<pid>/exe` for SO_PEERCRED's pid, so a process that connected, handed its
  socket on and exited could be attested as whatever binary was later given its pid. The path now
  comes through the connecting process's own pidfd (SO_PEERPIDFD, Linux 6.5+) and is kept only while
  that process still holds the pid; an exited caller, or a kernel without SO_PEERPIDFD, gets no path
  selector.
- limitations.md no longer calls the served private CA hierarchy flows "remaining", and no longer
  says every CA the served signer mints is ECDSA P-256: a ceremony mints ML-DSA-44/65/87 when its
  `signature_algorithm` names one, and the offline-root import accepts ML-DSA roots too (DF-1, a
  build-list doc fix). The ceremony's refusal of an unsupported algorithm now lists every algorithm
  it accepts, ML-DSA included. A docs guard ties both statements to the routes and the key code.
- The IIS pool configuration digest reads its locked buffer only under the buffer's lock
  (ARCH-014). It read the region through `Buffer.Bytes()`, which releases the lock before the
  slice is used, so a concurrent destroy could wipe and unmap the private configuration under
  the copy or the hash; `TestSecretBufferBytesStaysDeadInCoreCryptoKeyPaths` was failing on it.
- A test now holds that a CSR's UPN `otherName` SAN never reaches a leaf trstctl signs
  (A160-L1). No profile can express a user principal name, and the leaf builder takes only
  the DNS, IP, email and URI names a profile checks; a mutant that copied the CSR's SAN
  through fails it.
- The signed webhook, Parameter Store and Netlify secret-sync targets are counted by the
  definition-of-done census (A202-L2). They were proved only by served tests, so the README's
  secret-sync row counted ten and named them apart. Each is now a census row (WIRE-SYNC-109 to
  111) proved through the production-assembled handler against the census vendor emulator,
  which checks the webhook's HMAC over timestamp and body, SigV4 for `ssm`, and Netlify's env
  API, and reads each value back; the row reads 13 inventory / 13 served.
- The machine-login review says whether the credential logs in once (M4-L1). OIDC and JWT
  logins are replay-guarded, so a token works once, but the preview never said so and a second
  test with the same token looked like a failure. The preview now serves `single_use` and
  `credential_reuse`, and the console shows it in the review.
- Lint covers the Go SDK module (A250-L1). No lint gate ran over `clients/sdk/go`, which left
  three gosec findings unseen: the idempotency key generator's `math/rand/v2` draws (a dedup
  token the server binds to the authenticated request, kept outside the crypto boundary by
  design under CRYPTO-101, now annotated with that reason) and a test's deliberate redirect
  fixture (annotated). `make lint` now runs golangci-lint in the SDK module from its own root.
- An access bundle naming an account the target registry cannot serve is refused when it is
  saved (A257-L4). A bundle could delegate an unregistered or disabled target, or a role the
  target does not allow, and was refused only when a run tried to open it. Saving now checks
  each `access_targets` entry against the registry and answers 422 naming the target or role.
- The console offers an authority for a rogue certificate from what the server says it can do
  (A163-L3). It kept its own copy of the kinds that revoke by serial or from a certificate's
  bytes, which could drift from the server's. `GET /api/v1/external-cas` now serves
  `revokes_by_serial` and `revokes_by_certificate` for each authority (false while it is
  unavailable), and the console filters on them.
- Resolving a third-party finding settles its provider annotation (A174-L1). The Slack reply,
  Jira comment, failed commit status or image referrer an annotation wrote kept telling people
  to rotate a credential after the finding was remediated or dismissed. The resolution now
  queues, in the same transaction, a control-plane row that deletes the Slack reply, rewrites
  the Jira comment to say the finding was resolved, sets the commit status to success under the
  same context, or deletes the image referrer.
- DigiCert and Sectigo domain validations are recorded like upstream ACME authorizations
  (A165-L2). The vendors' unattended DNS TXT validation left no record, so the upstream
  authorization freshness view showed nothing for them. Each validated name is now recorded as a
  `dns-txt` validation under the authority, and a name Sectigo already holds validated as a reuse.
- A moved leaked secret's consumers can prove the rotation through the KV-compatible surface and
  secret sync (P6-L4). Only reads through the native store's routes counted as a consumer
  picking up the rotated version, so a finding whose consumers read through `/v1/secret/data`
  or from a sync target never closed. Both now record the consumer read: a KV read with its
  reader, a sync delivery as `secret-sync:<target>`.
- A GitHub push hook delivery refused for its signature is an audit event (P6-L3). A missing or
  wrong `X-Hub-Signature-256` was answered with 401 and left no record. Each refusal is now a
  `secret.scan_hook.refused` event naming the hook, GitHub's delivery ID and whether the
  signature was missing or wrong, never the body or the signature.
- A refused ACME email reply is an audit event, not only a log line (P15-L9). The RFC 8823 reply
  intake bounced a malformed, unsigned, unmatched or wrong reply and wrote one log line in the
  process that read it. Each refusal is now an `acme.email_reply.refused` event with the step
  that refused it and the From domain, never the mailbox or the message.
- A check-out whose credential cannot be retired at its deadline raises an alert (A261-L2). When
  the rotation could not be queued (its provider removed or no longer rotating the role) the
  check-out stayed revealed past its deadline with nothing but a "rotation pending" label. It
  now raises one critical `pam.checkout.rotation_blocked` alert naming the check-out, target,
  requester and the refusal, and later ticks that still cannot end it raise no second one.
- A check-in while another rotation of the account is running ends the check-out on that
  rotation (A261-L1). It was refused with 409 until the rotation finished, and the deadline
  retried every tick. A rotation queued after the reveal replaces the revealed version, so the
  check-in, or the deadline, now adopts it and records it as the rotation that retires the
  revealed credential.
- A PAN-OS renewal picked up again after its certificate import finishes instead of stopping
  (PANOS-O1). PAN-OS replaces a job's pending request with the certificate imported for it, so
  a reclaim after a failed commit or a lost job had nothing left to sign and stopped. The relay
  now names the certificate the firewall holds; the control plane hands back the job's own
  signed result only when it is exactly that certificate, and the relay binds, commits,
  verifies and reports without a second signature.
- Renewing a Kubernetes TLS Secret in place keeps what other controllers set on it (K8S-O2).
  The update replaced the whole object, carrying only labels and annotations, so a renewal
  dropped the Secret's `ownerReferences`, its finalizers and data keys such as `ca.crt`. The
  agent now sends a JSON merge patch naming only the type, `tls.crt` and `tls.key`,
  conditional on the `resourceVersion` it read; a write without a key keeps the Secret's key.
- A cloud-store migration member whose store stays down fails its gate instead of waiting at
  it (A166-L4). A control-plane deploy or rollback that spent its retries recorded no verdict,
  so the run sat at its live gate where a relay would have reported a failed receipt. The
  spent row now counts as the member's failed answer: the run rolls the member back, or halts
  naming it when the rollback could not reach the store either, and one rollback retry once
  the store is back re-binds the predecessor.
- One access review campaign attests an owner once (Q1-L6). Every kept item appended its own
  ownership attestation, so an owner with several credentials in one campaign was attested
  as many times. A keep now records nothing more when the owner was already attested after
  the campaign began and its application and environment have not changed since.
- A stale-owner access review lists the credentials of owners that cannot be attested (Q1-L5).
  An owner with no application or environment can never be attested, and
  `stale_owner_attestation` skipped it, so no campaign ever brought it to a reviewer. Its
  credentials are now listed as "ownership incomplete"; a keep stays refused until the
  reviewer completes the owner.
- An SSH trust fleet rollout with a failed host reads `attention_required` even when other
  hosts are still queued past the window (A226-L3). `execution_window_expired` used to
  override it, so the rollout list read as a timing problem while a host had failed; the
  expiry still shows on its own as `window_expired`.
- A Kubernetes TrustBundle refuses a certificate that does not parse (TB-O1). The agent
  checked only that each PEM block said `CERTIFICATE`, so a truncated or garbled certificate
  reached ConfigMaps, Secrets and CSI volumes (only the API server's ClusterTrustBundle
  validation refused it). Every block must now parse, and the refusal names which one.
- A KMIP key that is not yet activated reconciles as disabled, not unknown (KMIP-O1). The
  KMIP reducer mapped Pre-Active to "pending", which the canonical status set does not have,
  so every reconciliation round reported such a key as drift. A Pre-Active object may not
  be used until activated (KMIP 1.4, section 3.22), so it is now `disabled`, as a
  deactivated one is; the mapping is spelled out state by state.
- The bulk-revoke contract names every permission it checks (N7-L1).
  `POST /api/v1/certificates/bulk-revoke` advertised only `identities:write`, but selecting
  exact certificates (`certificate_ids`) also needs `certs:issue` and is refused with 403
  without it. Operations now list such permissions in `x-trstctl-also-requires`
  (`permission` and `when`), and bulk revoke declares `certs:issue` for exact certificates.
- The access deletes' OpenAPI contract requires the `revision` the caller read (A261-L4).
  `DELETE /api/v1/access/folders/{name}`, `/auto-approval-rules/{id}` and
  `/gateway-pools/{name}` refuse a delete without it (400), but the served contract marked
  the query parameter optional, so a generated client could omit it. It is now required in
  the contract and the regenerated SDKs.
- An ACME finalize the certificate profile refuses answers the client's error (P15-L10). It
  answered `500 serverInternal` ("issuance failed: profile ... does not permit DNS SAN
  ..."), telling the client the server had failed, so clients retried a request that could
  never succeed. A name the profile does not permit is now `400 rejectedIdentifier` and any
  other refusal `400 badCSR` (RFC 8555 section 6.7), naming the refusal; a profile that
  cannot be evaluated stays a server error.
- A host renewal heals after a certificate authority outage with nothing cleared on the
  agent host (A36, an outside lab's DNS-01 test). A job whose CA attempt was left
  unconfirmed could never finish, every retry answered 409, and once that job was
  cancelled the agent refused every later renewal of the target as "the encrypted pending
  host key belongs to another job" until a file was deleted by hand. Retrying a
  `renewal_failed` identity now ends a failed host job no agent holds (and withdraws the
  CA request it left waiting), each new job tells its agent through which job the target's
  renewals have ended, and the agent wipes a key one of those jobs left unsigned. An
  outage the CA reports as not submitted still heals by the same job's next attempt.
- A secret rotation schedule or MDM SCEP policy under a name another one holds is a 409,
  and nothing is recorded (LS-1, the rest of the class A233-L3 found). Each appended its
  event and then failed the projection on the tenant's name index (MDM SCEP policies in
  any case): a 500 from the API (the rotation schedule's refusal surfaced as the
  database's duplicate-key error) and an event a projection rebuild stopped at. Both
  commands now check the name under the projection lock before the append and answer the
  typed `name_held` problem, and such an event already in a log applies as the no-op it
  was live.
- A report schedule under a name another schedule holds is a 409, and nothing is recorded
  (LS-1, the class A233-L3 found). Creating one, from the API or a tenant baseline,
  appended the schedule event and then failed its projection on the tenant's
  schedule-name index: a 500, and an event a projection rebuild stopped at. The
  orchestrator now checks the name under the projection lock before the append, the API
  answers a typed `name_held` problem (audit feeds use the same refusal), and such an
  event already in a log applies as the no-op it was live.
- A second audit feed with a name another feed holds is a 409, and nothing is recorded
  (A233-L3). `PUT /api/v1/audit/feeds/{id}` appended the configuration event and then
  failed its projection on the tenant's feed-name index: the caller got a 500, and the
  event log kept an event no projection could apply, so a projection rebuild stopped at
  it. The name is now checked under the projection lock before anything is appended
  (preview answers the same 409), and such an event already in a log applies as the
  no-op it was live, so that log rebuilds and the name stays with the feed that held it.
- A tenant baseline's and a change set's profile digest is one `sha256:` and its hex
  (A248-L2). The profile step prefixed `store.ProfileSpecDigest`, which already carries
  the prefix, so drift, change-set plans and recorded template applications read
  `sha256:sha256:…` for profiles. Template applications recorded earlier keep the doubled
  form in their stored results; a provider rollout previewed before the upgrade is
  previewed again, since its fingerprint covers each object's digest.
- The Security scans' downloads retry a failed transfer. The gitleaks installer
  (`tools/gitleaks/install.sh`) and the Trivy step fetched their GitHub release files once,
  so a 504 from GitHub's release downloads failed the job without scanning anything (twice on
  2026-11-08). Each download now retries six times, ten seconds apart, inside the job's time
  limit; the pinned checksums still decide what is installed.
- Inventory pages sorted the whole tenant on every page: the page queries select the keyset column as `id::text`
  without an alias, and PostgreSQL resolves a bare `ORDER BY id` against that output column, so each 50-row page of
  the certificate inventory (and of identities, owners, issuers and 17 other keyset pages) was a sequential scan and
  sort of every row by its text form — 35 ms at 102,000 certificates instead of 0.25 ms — and every caller that walks
  the inventory (the API list, risk scoring, the graph build, revocation health, the weak-key audit) grew with the
  square of it. The pages now order by the table column; the order, pages and cursors are unchanged. Found by the A266
  scale harness.
- Keyed commands failed after a burst of commands that looked nothing up, such as an inventory import: the event log's
  identity index advanced only at startup and by a bounded step per lookup, so every issuance after a 20,000-row
  switching import refused with "event identity index is behind source history" until enough lookups had caught it up.
  The production event log now keeps the index within one lookup's reach in the background: one goroutine, woken every
  128 appends and every five seconds, indexes 256-event pages under the history read view and lock a lookup takes once
  the index is more than 512 events behind (under ordinary traffic the lookups keep it current, so it does no work). A
  lookup still refuses when the index is behind its bounded catch-up. Found by the A266 scale harness.
- Recording a certificate re-read the tenant's whole certificate history: the recovery that runs before each recording
  (it verifies the history against exact receipts and recovers an event a failed transaction left in JetStream)
  started after the new leaf's own head, which is the tenant's registration, so recording an inventory took time that
  grew with its square; the A266 harness's 50,000-row switching import stalled in its first export. Migration 0436
  keeps a recovery checkpoint on the tenant's metadata watermark row: a recording scans the history past it,
  re-verifies 16 events of the history below it (rotating, so the whole history is checked again continuously) and
  advances it in the same transaction, and a trigger marks any receipt whose sequence, identity or digest changes, so
  the next recording re-verifies from it and a corrupted receipt anywhere still refuses the append. A rolled-back
  recording, a rebuild, a snapshot restore or offboarding resets or keeps it consistently. Snapshot format 112.
- Mutations with a documented body above 1 MiB accepted no more than 1 MiB: the shared idempotency binding read every
  mutation's body under the REST limit first, so `POST /api/v1/switching/imports` refused (413) any export the preview
  had just mapped past about 2,500 rows (the kit takes 50,000 rows and 20 MiB), `POST /api/v1/ssh/krl/adoptions` any
  KRL over 1 MiB (4 MiB documented) and `POST /api/v1/owners/import` any CSV over 1 MiB (8 MiB). Each now binds its
  whole body up to its own limit, so a body that differs anywhere is a different command, a CSV over 8 MiB is refused
  rather than cut short, and a response recorded before the change still replays. Found by the A266 scale harness.
- Signed third-party scan artifacts accept binary RSA and ECDSA signatures whose first or
  last byte is whitespace. Only base64 text loses surrounding whitespace; changed artifacts
  and incomplete signatures remain refused.
- With `TRSTCTL_MIGRATE_AUTO=false` the startup gate counted core migrations only: an extension
  family's new migration passed it and was applied at startup, and `--migrate-status` did not
  list it. Both now read every migration source (A246).
- A tenant refusal answered bootstrap enrollment and the agent channel with the condition that
  refused it; every surface again answers "tenant service is suspended or offboarded", and the
  condition stays on the server.

- One operations view for rotation, revocation and proof (A245): `GET /api/v1/operations/ledger`
  (CLI `operations ledger`, the Operations page) lists certificate rotations, connector deliveries,
  secret rotations and approvals in nine normalized states — verified only on consumer evidence,
  uncertain when an effect's outcome is unknown; `GET /api/v1/operations/ledger/{id}` (CLI
  `operations ledger get`) shows one operation's causal chain and its exactly scoped retry and
  rollback; `GET /api/v1/identities/{id}/revocation-report` (CLI `identities revocation-report`, the
  revoked identity's detail) keeps CA status, deployed material, new connections and open sessions
  apart. An issuance approval now binds the platform CA when the identity names no issuer, so
  moving it to another CA supersedes the approval.
- Application view for certificates (A244): `GET /api/v1/identities/{id}/application` (CLI
  `identities application`, the console's **Application view** in an identity's detail) shows
  the owner, profile and its enrollment methods, the exact issuer, the destination and latest
  delivery, what was seen at the endpoint and from which vantage, approvals with what changed
  under them, the next automated action and failed prerequisites, recent alerts, the recover,
  revoke and retire actions, a value-free review plan and reusable defaults (the console carries
  them into the destination form). Identity list items carry `inventory_state`: requested,
  issued, delivered, served (shown as *Seen in use*), revoked or retired.
- Issuance approvals bind the destination and the issuer (A244): an approval asked for an identity
  that deploys to a target now records that target and its configuration revision, and the
  identity's issuing authority, in its evidence (covered by the intent digest). Editing the
  target, rebinding the identity, or a different issuer supersedes the approval when it is decided
  or used, as a changed profile already did. `GET /api/v1/connectors/targets/{id}/impact` and
  `GET /api/v1/profiles/impact/{name}` (CLI `connector target impact`, `profiles impact`) show what
  a change would reach: the certificates that use the target or profile, and the open approvals it
  would supersede.

- Secret migration runs (A243): `POST /api/v1/secrets/migrations/assess` reads an export in common
  formats — dotenv, JSON or YAML, per environment and folder — into native names
  (`<project>/<environment>/<folder>/<key>`), translates its references (`${NAME}`,
  `${folder/NAME}`, `${environment:folder/NAME}`) into `${secret.<name>}` so chains stay chains,
  keeps multiline values and metadata (description, tags, owner), and records a value-free plan
  bound by digest to the values it was made from: per object import, reissue (a credential the
  export could not carry) or blocked (a missing environment, an unresolved reference or a cycle,
  an environment the caller may not write, a secret another run's export still writes). Permissions
  translate only where nothing widens: an environment-wide read becomes viewer and write developer;
  folder grants, admin, wildcards, mixed access or an existing different membership are held for
  review, and an environment the export restricted that is open here blocks its objects unless
  accepted explicitly. `stage` imports by the digest as new versions (a stale digest is refused)
  while the export's system stays each secret's one writer — native writes, promotions and restores
  to those secrets answer 409 until cutover; `permissions` (access:write) applies only translated
  grants; each consumer's first read of its secrets, as its own subject, is recorded; `cutover`
  needs every consumer to have read; `reissue` issues new values for credentials the export could
  not carry, recorded as reissued and never as migrated; `rollback` restores the versions the run
  found, deletes what it created and keeps what changed since, converging when retried. CLI:
  `trstctl secrets migrate assess|list|show|stage|permissions|cutover|reissue|rollback`.

- Connector modules on the relay (A242): a third-party WASM connector now ships a signed
  manifest (`<name>.manifest.json` + `.sig`, signed by the key that signed the module) naming
  its version, the module's SHA-256, the host ABI range, its permissions (capabilities,
  host:port and path resources, and how the relay may add the target's credential: `basic`,
  `bearer` or `header:<Name>`), actions, idempotency and revocation behavior, setup inputs and
  limits. A module runs under exactly the grant its manifest asks for, which must fit the
  operator's `--connector-plugin-capability` grant (and `--connector-plugin-credential`
  ceiling); its memory and per-call time are bounded, and each module has its own worker pool
  so one that spins or floods cannot occupy another's. A module runs only once its operator
  approves it (`trstctl-agent --approve-connector-module <name>` prints the review and what it
  adds over the current approval, recorded in `--connector-plugin-approvals`); a later version
  that asks for no more loads under the same approval, one that asks for more, is older or comes
  from another publisher waits and is reported as awaiting approval. A failed module call
  reaches the control plane as exact evidence (name, version, digest, entry point and the class
  the host observed: trap, timeout, rejected, grant-denied or the status it returned) while the
  job stays queued; a `create-new` module's retry asks its `readback` first and does not repeat a
  deploy that landed, and a module's readback feeds the deploy's verification like a native
  connector's. `trstctl-agent --check-connector-modules` is the conformance kit. The relay's
  signed census carries each module's version, state, actions, idempotency, revocation, setup
  inputs, limits and health, and lists modules awaiting approval with what an approval would
  add (only loaded modules count as carried for routing and destinations). The connector
  catalog API returns it (`module` on each relay plugin), the Connectors console shows it,
  offers loaded modules as destination types with a setup form built from their inputs, and
  the API checks a module destination's configuration against those inputs (required, typed,
  secret inputs only as references).

- Integration catalogs say how far each entry is proven (A242): the connector catalog and the
  secret-sync target catalog carry `qualification` on one ladder (discovered, implemented,
  served, locally-proven, vendor-qualified). The sync catalog flags the signed webhook and
  generic CI JSON as `generic`, never native, and lists the integration catalog's unbuilt
  targets as `discovered` with a `note` on what each waits for. Both console catalogs show the
  rung.

- Hosted secret-sync targets (A241): `heroku`, `render`, `railway`, `fly`,
  `digitalocean-app-platform`, `northflank`, `qovery`, `cloud66`, `laravel-forge`, `circleci`,
  `travis-ci`, `bitbucket`, `teamcity`, `spacelift`, `humanitec`, `rundeck`, `checkly`, `windmill`,
  `zabbix`, `portainer`, `devin`, `daytona`, `ona`, `trigger-dev`, `cloudflare-workers`,
  `cloudflare-pages`, `cloudflare-secrets-store`, `azure-app-configuration`, `oci-vault`,
  `ovh-secret-manager`, `databricks-secrets`, `supabase-secrets`, `camunda` and `chef`, each
  bound by one `binding` string in its type's grammar (internal/synctarget) and run by one
  engine (`secretsync.HostedSyncPusher`). Every hosted target takes a scoped sync: it lists,
  reads back and deletes keys. A scoped sync to a flat (variable-name) destination joins its
  prefix without a slash and blocks a key the target can't hold; a receipt-only target (whose
  vendor never returns a secret) plans `unchanged` only when this version's delivery job
  succeeded and says a change made outside the sync can't be seen. The sync target catalog
  now says, per target, whether a scoped sync can target it (`scoped_sync`), what it reads
  back (`readback`) and how far it is proven (`proof`); the console's catalog shows both.
  Each target is proven through the served API against a stand-in built from the vendor's
  API reference (create, update, drift, delete, unmanaged keys kept, no value in a plan or
  the logs); none has a live account proof yet.

- Snowflake key-pair rotation (A240): a `snowflake` role bound to `user <NAME>` rotates that existing user's key pair in
  two phases through its two key slots; retirement unsets the predecessor's slot only while it still holds that key.
  Verified by `SELECT 1` as the user. Built against a stand-in of the SQL API.

- Google Cloud service-account key rotation (A240): `gcp-iam` providers with `allow_static_rotation` rotate a stored key
  in two phases (a new key beside the predecessor, deleted at retirement); verification reports `not_available`.

- Windows local account rotation (A240): `windows` providers rotate local account passwords on a Windows host serving
  OpenSSH, as an Administrators member authenticating with a key, the host key pinned; the only command is
  `Set-LocalUser`, its encoded script naming the account and the password on stdin. Two-user pairs and acknowledged
  in-place changes work as for `unix`. Proven on a windows-latest runner serving OpenSSH to itself.

- Okta and Databricks client secret rotation (A240): `okta` (an app's client secret, two per app) and `databricks` (a
  service principal's OAuth secret, five per principal) rotate in two phases and issue no leases. A rotation adds a
  secret beside the one in use and retirement removes the old one (Okta: deactivate, then delete); only secrets of a
  bound client are ever removed. Verified by client authentication at the vendor. Built against stand-ins.

- Azure Entra client-secret rotation (A240): `azure-entra` providers with `allow_static_rotation` rotate a stored
  client secret in two phases — a second password beside the predecessor, verified with a client-credentials token
  request at `authority_host`, and retirement removes only passwords the provider added (display name `trstctl-...`).
  Built against stand-ins of Graph and the identity platform.

- Hosted API key rotation (A240): `openrouter`, `fireworks`, `litellm`, `supabase`, `convex`, `dbt`, `cloudflare` and
  `cloudflare-r2` providers issue
  leases and rotate in two phases with one shared engine. Each key is created with the administrator's credential
  under the target the role is bound to (a credit limit, a user, a model list, a project, a deployment and its
  actions, a permission set, a template token's policies), named for the lease or command, and deleted at revocation only after the provider's
  naming is checked; a retried creation replaces its earlier attempt's key. Keys are verified with the vendor's own
  read where one exists (Supabase, Convex and R2 report `not_available`). Built against stand-ins of each vendor's API.

- SAP HANA dynamic secrets (`type: hana`): each lease is a user with a generated password and no password lifetime,
  granted only the existing HANA roles its role is bound to; the password and names travel only as parameters of an
  anonymous SQLScript block. Revocation deactivates the user, disconnects its sessions and drops it. Its lab test runs on
  an x86 CI runner against SAP HANA, express edition.

- Oracle Database dynamic secrets (`type: oracle`): each lease is a user with a generated password granted only the
  existing Oracle roles its role is bound to; the password and names travel only as binds, quoted by the database.
  Revocation locks the user, kills its sessions and drops it. A role with `rotation_accounts` instead rotates between
  two existing users (A240). Proven against Oracle Database Free (26ai).

- Cassandra dynamic secrets (`type: cassandra`): each lease is a login role with a generated password, granted only
  the existing Cassandra roles its role is bound to; only the password's bcrypt hash travels in CQL (`HASHED PASSWORD`).
  Revocation drops the role, so the next login fails and an open connection is refused once the node's caches expire.
  One node is contacted, over verified TLS or plaintext to a literal loopback or private IP. Proven against stock
  Apache Cassandra 5.0.9.

- Rotation library with consumer cutover (A240): two-user rotation for PostgreSQL, LDAP, MongoDB, Oracle, SQL Server
  (and Azure SQL contained users) and Unix/Linux local accounts (`rotation_accounts`): stage sets a new password on
  the account consumers are not using, retire sets one nobody holds on the other, and both keep their grants, roles or
  groups. `consumers` and `retire_after_seconds` hold the predecessor until the named consumers report the new version
  or an approved deadline passes, and the command view keeps `credential_valid` apart from `consumer_adoption`.
  Single-phase providers (`auth0`, an in-place `unix` account) run only with `acknowledge_single_phase`; `datadog` and
  `openai` keys issue leases and rotate in two phases. Proven against PostgreSQL, OpenLDAP, MongoDB 7.0, Oracle
  Database Free, SQL Server 2022 (x86 CI lab) and a Debian OpenSSH host; Auth0, Datadog and OpenAI are built against
  stand-ins of their APIs.

- IBM API Connect dynamic secrets (`type: ibm-api-connect`): each lease is a credential (client ID and generated secret)
  on the consumer app its role is bound to (`"<org>/<catalog>/<consumer-org>/<app>"`), carrying that app's
  subscriptions, created through the platform API with the api_key grant; revocation deletes the credential and the
  gateway then refuses its client ID. Built against a stand-in of the platform API.

- ElastiCache and MemoryDB dynamic secrets (`type: aws-elasticache`, `type: aws-memorydb`): each lease is an RBAC user
  with a generated password and the role's access string, compiled from literal key prefixes and explicit safe commands
  exactly as for the Redis provider (`redis_acl_roles`; raw ACL rules and categories are refused), added to one
  ElastiCache user group or MemoryDB ACL (`user_group`) once AWS reports the user settled. Revocation deletes the user,
  which AWS removes from every group and cluster. Requests are SigV4-signed with the configured access key. Built
  against stand-ins of the ElastiCache Query API and the MemoryDB JSON API.

- Snowflake dynamic secrets (`type: snowflake`): each lease is a Snowflake service user (`TYPE = SERVICE`) that
  authenticates with a key pair the provider generates (the lease returns the private key; no password exists, so none
  reaches SQL text or query history), granted only its role's roles and set to expire in Snowflake after the
  provider's maximum lifetime in whole days (`DAYS_TO_EXPIRY`). The administrator calls the SQL API with a key-pair JWT
  signed inside the crypto boundary. Revocation disables the user, aborting its running queries, then drops it. Built
  against a stand-in of the SQL API.
- Dynamic-secret providers that delete principals by name (ClickHouse, RabbitMQ, MongoDB Atlas, Kafka, Couchbase,
  Milvus, SQL Server, Azure SQL, Snowflake) now refuse to delete one without the full issued-name shape (prefix, role and
  the lease digest suffix), not just the prefix, so an administrator named, say, `trstctl_admin` is never deleted.

- GitHub App dynamic secrets (`type: github-app`): each lease is an installation access token narrowed to the role's
  permissions and named repositories (`"contents:read,metadata:read on api,web"`), minted with an RS256 app JWT signed
  inside the crypto boundary. GitHub ends a token after an hour; revocation ends it at once by presenting it (the lease
  keeps its sealed token until then), and a lease can't be extended. A token broader than requested is revoked and
  refused. Built against a stand-in of GitHub's API.

- SQL Server and Azure SQL dynamic secrets (`type: mssql`, `type: azure-sql`): an `mssql` lease is a login with a
  generated password and a user in the configured database that joins the role's database roles (`"db_datareader"`);
  an `azure-sql` lease is a contained database user. Revocation disables the login, ends the principal's open sessions
  (SQL Server keeps a dropped principal's sessions) and drops the user and login. The password reaches SQL Server only
  as a parameter, never in statement text. Their lab tests run against SQL Server 2022 Developer Edition on an x86 CI
  runner (the image is x86 only); Azure SQL is proven through SQL Server's contained database users.

- Milvus dynamic secrets (`type: milvus`): each lease is a Milvus user with a generated password and only the Milvus
  roles its role is bound to (`"orders_reader"`), created through the RESTful API; revocation drops the user (and its
  role grants) and Milvus refuses its next request. Proven against stock Milvus 2.6.26 standalone.

- Couchbase dynamic secrets (`type: couchbase`): each lease is a local Couchbase user with a generated password and
  only its role's roles on the named buckets (`"bucket_full_access on orders"`, the Community Edition's data role, or
  Enterprise roles such as `"data_reader,query_select on orders"`), created through the management REST API;
  revocation deletes it and Couchbase refuses its next request. Proven against stock Couchbase Server Community 8.0.2.

- Kafka dynamic secrets (`type: kafka`): each lease is a SCRAM-SHA-512 user with a generated password and only its
  role's ACLs on topics, consumer groups and transactional IDs (`"read,describe on topic:orders; read on
  group:orders-app"`; a trailing `*` makes a prefix). Revocation deletes the ACLs, which refuse a client still
  connected on its next request, then the credential, so the next login fails. Brokers are reached over verified TLS
  (SASL_SSL), or SASL_PLAINTEXT to a literal loopback or private IP only. Proven against stock Apache Kafka 3.9.0.

- MongoDB Atlas dynamic secrets (`type: mongodb-atlas`): each lease is a database user in one Atlas project with a
  generated password and its role's built-in roles (`"<role> on <databases>"`), which Atlas deletes after the
  provider's maximum lifetime (`deleteAfterDate`, at most 7 days); revocation deletes it. The Admin API is called with
  a service account's token. Built against a stand-in of the Atlas Admin API.

- Tailscale dynamic secrets (`type: tailscale`): each lease is a single-use, ephemeral, preauthorized auth key carrying
  its role's ACL tags and expiring with the provider's maximum lifetime; revocation deletes it. The key request is
  never retried blindly. Built against a stand-in of Tailscale's API.

- RabbitMQ dynamic secrets (`type: rabbitmq`): each lease is a RabbitMQ user with a generated password and its
  role's permissions in one virtual host (`"<permissions> on <queues or exchanges> in <vhost>"`, names matched
  exactly), created through the management API as `admin_user`; revocation deletes the user and closes its open
  connections.

- Elasticsearch dynamic secrets (`type: elasticsearch`): each lease is an API key, created by `admin_user`, that
  expires with the provider's maximum lifetime and holds only the index privileges its role is bound to
  (`"<privileges> on <index patterns>"`); revocation invalidates it, and a retry first invalidates any key an
  uncertain attempt left for the lease.

- ClickHouse dynamic secrets (`type: clickhouse`): each lease is a ClickHouse user with a generated password,
  valid until the provider's maximum lifetime and holding the ClickHouse role its lease role is bound to, created
  through the HTTP interface as `admin_user`; revocation drops the user, and a retry replaces the same user.

- OAuth 2.0 access-token dynamic secrets (`type: oauth-client-credentials`): each lease is a new token from an
  authorization server's token endpoint (client credentials grant) carrying only the scopes its role is bound to;
  a token with other scopes, another type or a lifetime outside the lease and `max_ttl` is refused (and revoked
  when possible). A token can't be extended. With `revocation_endpoint` revoking the lease revokes the token there
  (RFC 7009) and the catalog marks the provider confirmed; without it the revocation stays pending until the
  token's expiry (TTL-only). An uncertain token request is never retried blindly.

- TOTP dynamic secrets (`type: totp`): each lease carries the current RFC 6238 code of a seed the control plane
  holds and `valid_until`, the end of its time step; the code can't be renewed or withdrawn, so the catalog marks
  it TTL-only and `max_ttl` can't exceed the period.

- LDAP dynamic secrets (`type: ldap`): each lease is a directory entry with a password the directory sets and hashes,
  in the group its role is bound to, deleted at revocation, over LDAPS verified against the configured server name.
  The dynamic-secret provider catalog now states each adapter's authority and whether its revocation is confirmed or
  TTL-only.

- Secret rendering for host applications: `trstctl-agent --secret-render-config` keeps `{{ secret "name" }}`
  templates rendered into files with atomic writes and the file's mode, runs the application's reload hook, and
  asks the application to prove it uses the new value. Delivery reports (`trstctl-cli secrets deliveries
  report|list`) keep "injected" apart from "verified", and a control-plane outage keeps the last file only until
  its freshness bound, across agent restarts. Templates can use dynamic leases (`{{ lease "provider/role" "field" }}`):
  a lease is renewed in place or replaced, and the replaced lease is revoked only after the application verifies the
  new credential.
- Secret volumes for pods (`deploy/kubernetes/csi-secrets.yaml`, CSI driver `secrets.csi.trstctl.com`): a pod names
  its secrets in an inline CSI volume, and the node plugin reads them with the pod's own service-account token into a
  memory filesystem it mounts, with no Kubernetes Secret object. Republishes deliver new versions (reported as
  injected), remove a file the pod may no longer read, and apply a freshness bound while the control plane is away.

- Scoped secret sync: `trstctl secrets scoped-syncs define|preview|apply` keeps every secret under a source prefix
  in step with a KV v2 destination under a prefix. The value-free plan lists create, update (with drift named),
  delete within the reviewed scope, and keys the sync didn't write, which it never touches; nested-key and
  two-source collisions are blocked, a changed source or destination makes the plan stale, and a crash after a
  remote write settles by reading the destination back. An `auto` scoped sync is applied by the control plane when
  its sources change (nothing blocked); a blocked plan is recorded and waits for review. The console's Secrets →
  Sync page defines, previews, applies and switches scoped syncs.

- Folder restore for secrets projects: `trstctl secrets projects restore preview|apply` puts an environment or a
  folder back to a point in time as new versions in one batch, keeps secrets created since, and refuses a version
  whose credential a rotation retired, revoked or let expire. The console's project page offers Promote or restore.

- Environment promotion for secrets projects: `trstctl secrets projects promote preview` returns a value-free plan
  (per key: create, update, unchanged or blocked, plus the target secrets left alone) and its digest, and
  `promote apply` writes the plan as one batch of new versions when the digest still matches. References into the
  source environment are pointed at the target. A reference cycle, an ungranted restricted hop, a reference that
  exists only in another tenant, an unresolvable reference or a retired source credential blocks the promotion,
  and a secret changed after the preview makes the plan stale.

- Secrets projects and environments: `trstctl secrets projects create|show` and `members grant|revoke` group an
  application's secrets by environment (by name, `<project>/<environment>/…`) in the same native store. A restricted
  environment is readable and writable only by members granted it, on every surface including references and the
  Vault-compatible KV routes; a denied read answers as a missing secret. Membership changes need `access:write`, and
  the project view names unknown ownership. The console's Secrets → Projects and environments page shows them, with
  the owner's certificates and identities and their expiry health beside the secrets.

- An SMTP reply intake for ACME email challenges: `protocols.acme_email.smtp_listen` receives RFC 8823 replies for
  the challenge address only, verifies each one's DKIM signature for its From domain (rsa-sha256 and
  ed25519-sha256, keys from DNS or pinned in `dkim_keys`) and hands it to the ACME server; a reply that fails is
  refused with a 5xx reason so it bounces to the sender. STARTTLS is offered when the control plane has a certificate.

- S/MIME certificates over ACME (RFC 8823): with `protocols.acme_email`, an ACME client orders an `email`
  identifier and answers the `email-reply-00` challenge. The server mails token-part1 through the outbox and the
  configured SMTP relay, verifies the reply against stored digests (a wrong mailbox or token validates nothing, and a
  wrong response invalidates the challenge), and issues a signing-only certificate with the emailProtection EKU and
  the address as its only SAN. A CSR that asks for encryption is refused.

- Move a leaked secret into the vault: `trstctl secrets scans move <finding-id> --repo <checkout> --name <secret>`
  re-finds the value a redacted repository finding names in your own checkout (the pinned gitleaks, its report on a
  pipe), stores it as a native secret and links the finding with
  `POST /api/v1/discovery/findings/{id}/secret-move`; no value reaches a finding, event or log. The finding closes
  as remediated only after the secret is rotated, a consumer reads the rotated version and a completed scan no longer
  sees the leak; a failed scan never closes it, and the history commits that held the value stay listed on it.

- Native GitHub webhooks for repository secret scanning: `secrets.scan_webhooks` names a hook and its secret, and
  `POST /api/v1/secrets/scans/hooks/{id}` verifies GitHub's `X-Hub-Signature-256` before queueing a scan of the
  pushed commit; a wrong or missing signature is refused and redeliveries queue nothing new.

- OAuth token exchange (RFC 8693): `POST /oauth2/token` swaps a workload's platform token (a Kubernetes projected
  service-account token, a CI id_token) for a five-minute, scoped JWT-SVID signed in the isolated signer and
  verifiable offline against `GET /oauth2/jwks`; subject tokens are single-use and every exchange is recorded.

- Single-use machine login tokens: an `oidc` or `jwt` login token is recorded (as a digest) until it expires and
  refused if presented again, on any replica and across restarts; a token refused for another reason never uses up
  a valid one.

- Misuse detection (Enterprise governance): from trstctl's own usage record, a dynamic-secret lease requested from a
  client network the token has not used on three days, and an hour of secret reads well above the token's baseline,
  each raise one finding and one alert with evidence on the risk notification route; repeats fold into the day's
  finding and alerts are capped per tenant per hour.

- Usage-based posture from trstctl's own activity: API-token requests are recorded with their client network and
  action (bounded: one event per token, network, action and hour plus doubling counts), machine logins count as
  uses of their login method by the attested workload, and `GET /api/v1/nhi/posture/stale?unused_days=N` (CLI
  `--unused-days`) flags credentials with no recorded use for N days and use from a source not yet seen on three
  days — with no operator input. A recorded telemetry gap suspends "unused" instead of counting as non-use; the
  graph shows each token's last use.

- Access graph, step 2: a dynamic-secret lease now shows what its login reaches, read from the target. A
  PostgreSQL lease links to its database with the login role and the grants PostgreSQL reports for it; an AWS
  STS lease links to the IAM role it assumed with the role's attached and inline policies from IAM
  (`dynamic_providers[].iam_endpoint`, default the partition's IAM). The leader reads new leases within a minute
  and every lease every six hours, changing nothing upstream; a target it cannot read shows the grants as
  `unknown` with a reason and is retried, never shown as having none.
- Code-signing keys in an HSM or cloud KMS: `code_signing.keys[].managed_key_provider` and `managed_key_id`
  bind a code-signing key to an Enterprise managed key instead of a signer handle; startup checks it is active
  and of the configured algorithm. Every signature runs in the provider through the isolated signer, which now
  journals managed-key signatures by operation id (`SignManagedKeyRequest.operation_id`), so a retried signing
  command gets the same signature instead of a second one.
- Signing approvals with stock tools: while a code-signing approval is pending, the Notation plugin and the
  PKCS #11 module hold the tool's request open and sign once an approver grants it (`TRSTCTL_APPROVAL_WAIT`,
  default ten minutes); a denied or expired approval stops the tool with the reason. The signing mechanism
  is part of what is approved (`pkcs11:CKM_ECDSA_SHA256`, `notation:ECDSA-SHA-256`).
- PKCS #11 module for code signing: `libtrstctl-pkcs11` (`make signing-clients`, in `clients/signing`) offers
  trstctl code-signing keys to jarsigner, osslsigncode and other PKCS #11 tools. The PIN is the API token,
  each key comes with its certificate chain, the private-key handles are never extractable, and each
  signature (ECDSA P-256 or RSA, SHA-256) is made by trstctl's signer and checked against the certificate
  before the tool gets it. A refused signature is `CKR_FUNCTION_REJECTED` with trstctl's reason.
- Signing with stock tools: a code-signing key's certificate chain can be configured beside it
  (`code_signing.keys[].certificate_chain_file`, checked against the key at startup) and is served at
  `GET /api/v1/code-signing/keys/{key_id}/certificate`; `POST /api/v1/code-signing/keys/{key_id}/csr`
  returns a certificate request the key signs inside the signer, recorded as `codesign.csr_signed`. The new
  `clients/signing` module (MPL-2.0) adds `notation-trstctl`, a Notation plugin that signs through the
  code-signing API, and cosign can attach a trstctl signature that stock `cosign verify` accepts. The key
  never leaves the signer, and a refused request stops the tool with trstctl's reason.
- Planned CA switch: a migration run started with `revoke_predecessors` moves each cohort to the new issuer
  and revokes every previous certificate (superseded) through the CA that issued it, but only after the
  endpoint serves the new chain. A failed canary pauses the run with nothing revoked; resuming retries exactly
  the failed members as the same jobs, so no second successor is signed; starting the same switch again changes
  nothing.
- Audit feeds to syslog and Elasticsearch: beside Splunk HEC and Sentinel, an audit feed can deliver to a
  syslog receiver over TLS (`syslog+tls://host:6514`; RFC 5424 messages, octet-counted as RFC 5425 requires;
  the receiver is verified through the system roots or a CA certificate reference) or to an Elasticsearch
  bulk endpoint (`https://host/<index>/_bulk`, API key reference). Every collector receives the same audit
  records in sequence order with the chain trailer; a redelivered batch adds nothing to the index, and a
  stalled receiver holds only its own queue.
- Persistent DNS validation (dns-persist-01, the IETF draft): the ACME server offers it when
  `protocols.acme_dns_persist.issuer_domain_names` names this CA, and each order validates against the
  applicant's standing `_validation-persist` TXT record for this CA and account, so renewals need no DNS
  change; a deleted record or one naming another account refuses the next order. An ACME authority with
  `upstream_dns_persist` answers the challenge by publishing that record once through the DNS-01 provider
  configs and never retracting it. Proven against Pebble 2.10.1.
- CBOM import and code and image scanning: `POST /api/v1/cbom/imports` (`trstctl-cli cbom import --source
  vendor:|source:|image:<name>`) merges a vendor's, a code scan's or an image scan's CycloneDX CBOM into the
  crypto inventory with its source in every location; importing the same BOM again changes nothing.
  `trstctl-cli cbom scan-source` finds RSA, ECDH, ECDSA and legacy algorithms in Go, Java and Python code
  with file and line, and `trstctl-cli cbom scan-image` runs an installed CBOM scanner over an image,
  directory or archive; both run offline. Discovery coverage counts vendor, source-code and container-image
  crypto as observed while an import is recent.
- Closed-loop verification for migrations: a run started with `require_observed_traffic` advances each wave only
  when the live receipt and an observer agent's new connections at every endpoint agree, pauses when the wire proof
  is late, and then marks the observer's finding for the old certificate remediated naming both proofs.
- Passive network crypto observer: an agent granted the new observer role and started with
  `--observe-interface` reports, from the handshakes it sees, each endpoint's TLS version, cipher suite and
  key-exchange group (X25519MLKEM768 by name), TLS 1.2 certificates, SSH key exchange and plaintext
  HTTP/LDAP, never payload. The server accepts observations only from the observer role, and passive traffic
  is now an observed class in discovery coverage.
- Keystores and crypto libraries on hosts: `--inventory-keystores` reports each key entry of a Java
  keystore or PKCS#12 file (alias, key type and size, public-key fingerprint; no key material leaves the
  host, and a JKS key is never decrypted), and `--inventory-crypto-libraries` / `--inventory-go-binaries`
  report OpenSSL and Go versions with whether each can negotiate X25519MLKEM768. CBOM host-config scans
  now read HAProxy, Envoy, the OpenSSL configuration file and `java.security`; a HAProxy file that allows
  TLS 1.0 raises one weak finding.
- Access reviews that act: a revoke decision revokes the reviewed PAM session, API token, machine
  session or dynamic-secret lease once (an exact retry replays, a second decision is refused) and the
  item closes only when the credential reads revoked, with that evidence; a keep decision renews the
  owner's attestation and sets a next review date. `POST /api/v1/access/reviews/generate`
  (`trstctl-cli access reviews generate`, console) builds a campaign from who can reach a resource in the
  access graph or from owners whose attestation is stale. Decoy logins no longer appear in the graph.
- Decoy secrets: register a stored secret as bait (console, `trstctl-cli secrets honeytokens secrets`,
  `/api/v1/secrets/honeytokens/secrets`). Every read of its value through the API, its history, a
  resolved reference or the Vault-compatible API raises one critical alert per reader, naming who read
  it; listing names, metadata, previews, inventory and the graph never alert. Only people who can plant
  decoys see which secrets are bait.
- One-call revoke of an AI agent identity: `POST /api/v1/broker/agent-identities/{id}/revoke`,
  `trstctl-cli broker agent-identities revoke` and a console action in the broker record revoke that one
  broker certificate exactly like the revocation center (CA ledger, signed CRL, OCSP, agent key set), naming
  who revoked it. Broker issuance now records who asked for each identity, so the credential graph shows
  person → agent → credential → the tools its scopes name.
- Decoy database logins: a PostgreSQL dynamic-secret provider that lists the role `decoy` mints a login
  that reaches only its own empty database and looks like any generated login (console,
  `trstctl-cli secrets honeytokens databases`, `/api/v1/secrets/honeytokens/databases`). trstctl never
  uses it, so the first login with it raises one critical alert; probes and administration never do.
- Who can reach a database, host or API: the credential graph now holds people (tenant members),
  their roles and AI agents (from agent-broker issuance), with the credentials they hold (API
  tokens, machine sessions, PAM sessions, dynamic-secret leases) and the approvals behind them.
  `GET /api/v1/graph/reachers/{id}` (`trstctl-cli graph who-can-reach`) names each credential that
  reaches a node, who holds it and who approved it, every link with its record and confidence, and
  states what it cannot see; `GET /api/v1/graph/path` (`trstctl-cli graph path`) returns the path
  from one node to another. A PAM session now records the approval it consumed. The Graph page
  shows the new node kinds and both questions.
- CycloneDX 1.6 CBOM export of the crypto inventory: one cryptographic-asset component per asset
  with algorithm, key size, quantum security level, protocol and where it was observed, a coverage
  statement, signed with the audit evidence key and verifiable offline with
  `trstctl-cli cbom verify-cyclonedx`; a console download and a CLI export.
- Hardware attestation for PKCS#11 edge CA keys: a token's own attestation of the key (read by the
  agent from the token's certificate objects) that reaches a vendor root the segment pins records
  the delegation as hardware-key attested, with the device serial and key policies; a segment can
  require it.
- Annotate a leaked credential where it was seen: a third-party scan finding from a Slack export,
  a Jira export, a CI log or a container image can be written back as a thread reply, an issue
  comment, a commit status at GitHub or GitLab, or an OCI referrer on the image, by an operator or
  automatically, naming the rule and the finding and never the secret.
- Code-host secret stores in discovery: GitHub Actions secrets (repository, environment and
  organization; metadata only) and GitLab CI/CD variables (project and group, hidden variables
  flagged), with the same optional content inspection for certificates and credentials.
- API keys, tokens and private keys inside external secret stores: with content inspection, a
  cloud secret source checks each value it reads from AWS Secrets Manager, Google Secret Manager,
  Azure Key Vault or Vault KV against built-in credential rules and records each match with its
  rule, field, a masked display and a fingerprint shared by every copy of the credential; the value
  is wiped and never stored.
- Act at the identity provider on an abusive OAuth grant: an OAuth grant finding can revoke the
  user's grant at Okta, Microsoft Entra or Google Workspace, and block the app at Okta or Entra,
  through an admin connection the discovery source names by token reference.
- Workload identity for the Azure managed-key signer: `managed_keys.azure.workload_identity` exchanges
  the platform's projected federated token for short-lived Entra tokens, replacing the static bearer
  token file.
- Cross-reconciliation of an AWS KMS account against trstctl's managed-key record: an `awskms`
  authority source and a `managed_keys` authority, so a reconciliation round witnesses keys only
  one side holds and keys whose state drifted.
- Attack-path validation for exposed NHIs: a cloud network paths source with an AWS account's
  read-only credentials answers, per public endpoint, whether the account's route tables, network
  ACLs and security groups admit the internet, and names the resource that decides it.
- Cloud certificate stores in CA migration runs: a GCP Certificate Manager target that names a
  certificate map entry joins a run with no agent; the control plane installs the successor, reads
  the entry back as the live gate and re-binds the predecessor on rollback. AWS Certificate Manager
  and Azure Key Vault are refused at start with the reason they cannot restore a predecessor.
- Unattended domain validation for DigiCert and Sectigo: with `upstream_dns01`, trstctl completes
  CertCentral's DNS TXT validation and Sectigo SCM's TXT domain control validation through the
  tenant's DNS-01 provider configs (`allow_upstream_dv`), under the same CAA check and retraction as
  ACME upstream validation.
- Revoke a rogue certificate at its issuer: a certificate found in Certificate Transparency (for
  example one issued in your own vendor account outside trstctl) is revoked by serial at the
  external CA you name, and the finding shows revoked once the CA confirms; inventory findings
  revoke through the exact revocation.
- Upstream revocation for DigiCert, Sectigo, Venafi, AWS Private CA, Google CAS and step-ca: a revoke
  through trstctl reaches the vendor's API with the reason, the certificate shows revoked in
  inventory, and a retry changes nothing; the issuer capability matrix now shows revoke for each.
- AD CS revocation through trstctl: an `adcs` issuer that names a `revocation_relay` hands each
  revocation to that domain-joined relay, which revokes with certutil, publishes a new CRL and reads
  the row back before trstctl records the certificate revoked.
- AD CS CA database reads through a relay: a domain-joined network relay runs certutil against one
  CA as its own domain identity and returns only per-disposition counts (issued, pending, revoked,
  denied, failed), queued from the Posture panel, the API or the CLI; a failed read shows the relay's
  reason and keeps the previous counts.
- AD CS issuer health: `GET /api/v1/adcs/issuers/health` (CLI `trstctl adcs issuers health`, console
  Posture → AD CS issuers) reports healthy, degraded, failing or idle for each AD CS issuer from its
  recorded issuances and diagnosed refusals, with the latest cause and remediation. AD CS template
  permission denials (0x80094012) are now diagnosed as such instead of unknown.
- "Modernize this template": an inventoried AD CS template becomes a trstctl profile with its
  risky properties removed (names confined to its DNS domain so the requester no longer supplies
  the subject; Any Purpose, Smart Card Logon, PKINIT and Certificate Request Agent usages dropped;
  manager approval kept as dual control; 90-day validity), from the AD CS posture grid, the API
  (effect-free preview first) or the CLI.
- ACME and EST in front of AD CS templates: a certificate profile's `upstream_external_ca` routes
  protocol enrollments under it (ACME, EST, SCEP, CMP) to a configured external CA such as an
  `adcs` entry, after the profile's checks pass; the client receives the upstream leaf and chain.
  Console rule builder, API (unknown upstreams refused at save) and OpenAPI carry the field.
- Kerberos authentication for AD CS Web Enrollment: an `adcs` external CA can name a realm,
  principal, KDCs and a keytab (`kerberos_*`); trstctl answers the Negotiate challenge with a
  fresh service ticket per request and never holds or sends a password. Kerberos and Basic are
  mutually exclusive, and a Kerberos failure never falls back to Basic.
- Intune reads without a hand-rotated bearer: an Intune MDM poll schedule can name an Entra app
  registration (`client_credentials`: directory and application (client) ID); `token_ref` then
  holds its client secret and the network relay exchanges it for a Microsoft Graph token on each
  read (OAuth client-credentials grant, token held only in memory). Console schedule form, API and
  OpenAPI carry it; the Intune report export moved to Graph v1.0.
- Dynamic SCEP challenges for Jamf Pro and other MDMs that fetch a one-time challenge per device
  (`hmac-dynamic`): a policy names a `challenge_credential_ref`, the MDM fetches each challenge
  from `/scep/mscep_admin/{policy id}` with that credential (Jamf Pro: Dynamic-Microsoft CA), and
  the SCEP gate verifies it against the policy it names and consumes it once in the durable
  replay fence. Console, API and CLI carry the credential reference and the challenge page path.
- Tenant download of its own signed audit archives: with the separate `audit:archive.read`
  permission, `GET /api/v1/audit/archives` lists the tenant's archived segments and
  `GET /api/v1/audit/archives/{id}` returns one (`?format=jws` for the raw segment; CLI
  `trstctl audit archives list|get`; console Audit → Archived segments). Segments are addressed by
  opaque ID only, verified as the tenant's own signed retention segment before release, rate
  limited per tenant, and every download is recorded as an `audit.archive.downloaded` audit event
  first. A downloaded segment verifies offline with `trstctl audit verify --format retention-jws`.
- Event-field protection (crypto-shred) opt-in: a tenant can read its protection state, preview
  and enable per-tenant encryption of its sensitive event fields through
  `/api/v1/privacy/event-protection` (CLI `trstctl privacy event-protection`, console Privacy
  panel), naming its current registration and a retention window its policy chooses. A bounded
  worker prepares the key; status reads `active` only after the key reads back. After
  offboarding and the retention window, the key is destroyed with a signed record, and a rebuild
  or a restore of an earlier backup shows the tenant's sensitive fields as erased while audit
  verification and other tenants are unaffected. Events recorded before activation stay readable.
- Named ServiceNow and Jira ticket-intake schedules with independent relay jobs
  and cursors, explicit mailbox-to-owner mapping, and an Approvals setup wizard.
  Legacy sources remain `default`; removal preserves history and blocks active
  work. Missing or ambiguous ownership remains visible and cannot bypass issuance.

- Opt-in certificate CI export through a separate tenant-bound ServiceNow write
  binding. The outbox worker uses IRE and independently reads the fixed certificate
  class before recording a durable verification receipt. API, CLI and console show
  queue and verification status; ownership reconciliation remains read-only.

- Per-tenant private HTTPS notification receivers: an operator can grant exact
  networks through `notifications.tenant_private_egress`. API endpoint validation
  and outbox delivery use the same tenant grant. Tenants cannot grant themselves
  access; DNS, redirect, TLS and air-gap checks remain in force.

- Provider console sign-in through OIDC: with `provider.oidc.login` configured, the Provider console
  signs operators in with the IdP's authorization code flow (state, nonce and PKCE S256) and holds
  an HttpOnly, SameSite=Strict Provider session instead of a pasted bearer token. The ID token is
  verified offline against the pinned keys with the client id as audience and the same role and
  MFA claims; no token reaches the browser, every request re-reads the SCIM directory row, and
  sign-out revokes the session.
- Provider SCIM group removal: removing an operator from the `provider-admin` or
  `provider-operator` group through SCIM now revokes that role, recorded as a
  `provider.operator.role_revoked` authority event naming the group and the SCIM token, instead
  of being refused. Group PATCH applies its operations in order (the Okta and Entra request
  shapes), replace and PUT revoke whoever they leave out, and the operator stays active with no
  role, which OIDC and SAML refuse on the next request. A user created without roles holds none
  until a group push assigns one, and `GET /Groups` answers a `displayName` or `id` filter. The
  access console shows such an operator as holding no role.
- Attested edge delegation renewal: a segment policy can set `renewal_enabled` (with
  `renewal_window_days`, default 7), and a host agent run with `--edge-renew` renews its delegated
  edge CA over the agent channel inside that window. The TPM key signs a fresh CSR and TPM2_Certify
  vouches for it over the new challenge; the control plane holds the renewal to the mint's gate
  (one attestation verifier for both), requires the same delegated CA key, and mints a delegation
  with the old one's lifetime, linked by `renewed_from` and `renewed_by`. An expired, revoked or
  already renewed delegation does not renew, and a refused attestation leaves it to expire. The
  console's segment form has the renewal setting and the delegation list shows renewals.
- Edge journal upload: a host agent run with `--edge-journal-upload` sends its edge issuance journal
  over the mutual-TLS agent channel when it connects, after a heartbeat that follows failed ones,
  and when the journal grows, so issuances made while the host was offline reconcile without an
  operator posting the file. The control plane reconciles each certificate against the delegation
  of that host that issued it (the host is the agent's channel certificate name; host-role agents
  only), through the same path as the CLI and console reconcile, with the agent as the actor. The
  agent records the acknowledged prefix in `<journal>.uploaded` and sends only new entries.
- External CA ledgers in reconciliation: a reconcile authority can read an EJBCA CA's issuance
  ledger (`ejbca` source: REST v2 certificate search over mutual TLS) or a step-ca CA's (`stepca`
  source: its PostgreSQL `x509_certs` and `revoked_x509_certs` tables, read-only), and an
  `inventory` source scopes the certificate inventory to the same CAs. A round between the two
  witnesses drift both ways: certificates the CA issued that the inventory lacks, certificates the
  inventory holds that the CA never recorded, and revocations only one side knows. Both sides read
  the CAs in `issuer_certificates_file` and certificates unexpired at the observation, identity
  from each certificate's DER. A ledger that moves during the read, or is larger than
  `max_objects`, fails the observation instead of reporting part of it. The ids `trstctl-self` and
  `trstctl-ca` now refuse a source block.
- Hybrid-to-pure ML-DSA certificate cutover: a PQC migration run can target pure ML-DSA for a
  certificate whose current leaf is the hybrid composite (the console offers such certificates).
  The plan marks that reissue `cutover`; starting the run holds its host job, the finding reads
  `awaiting_acknowledgment`, and the start response counts it in
  `certificate_cutovers_awaiting_acknowledgment`. Once a quorum of signed relying-party
  acknowledgments for the identity's PCAS retirement policy is recorded inside its window (a policy
  PCAS already retired on that quorum still counts), a leader worker queues the held job unchanged
  and records `pqc.migration.cutover_released` with the relying parties and the ack-set digest; the
  host then generates the ML-DSA key and returns only its CSR. Without the quorum the cutover waits
  and the served leaf stays hybrid.
- Scheduled CA rollover drafts: with `ca.rollover_draft_band_months` (`TRSTCTL_CA_ROLLOVER_DRAFT_BAND_MONTHS`,
  off by default) set to a CA calendar band, an active signer-backed authority entering it gets a
  `rekey_ca` ceremony opened for it with the reviewed plan — its profile and lifetime and a
  scheduled-rollover reason — at the approval floor. `GET /api/v1/ca/authorities` and the CA console
  show the draft and its approvals; nothing rotates until custodians approve and a person executes
  the re-key with that plan. An authority that cannot be re-keyed online records why.
- Certificate byte recovery: `POST /api/v1/certificates/{id}/der-recovery` (`trstctl-cli
  certificates recover-der`, the certificate detail's **Certificate bytes** actions) gives an
  inventory row recorded without its certificate — a scan, a cloud listing, an older import — the
  certificate itself, from a mint of the tenant's CAs that retained it (`ca_ledger`, by serial) or
  from the `host:port` the row names (`endpoint`, dialed by the control plane under the egress
  rules). Bytes are attached only when they hash to the row's fingerprint and the row held none,
  with where they came from; the row then joins authority agreement checks. Certificate responses
  carry `certificate_bytes_held`, and the detail `der_recovery`.
- Verification address suggestions: `GET /api/v1/connectors/targets/{id}/verification-suggestions`
  (`trstctl-cli connector target verification-suggestions`) lists the `host:port` addresses where a
  discovery scan saw a certificate trstctl delivered to the target, with those findings as
  evidence, and `POST /api/v1/connectors/targets/{id}/verification-address`
  (`connector target confirm-verification-address`, the console's **Verification address** panel)
  sets one as the target's `verify_address` only when an operator confirms it — never an address
  no finding suggests, and never on a target that changed since the suggestions were read.
- Certificate Transparency SCT verification and inclusion proofs: a CT submission can name
  each log's public key in `log_public_keys` (the console takes it after the log's URL).
  Every SCT a log returns is kept: verified against that key over the exact RFC 6962
  entry (the certificate, or a precertificate's issuer key hash and TBS) or flagged invalid
  with the reason; a log without a key keeps its SCT unverified and the response says so.
  For each verified SCT the leader fetches the log's signed tree head, checks it with the
  same key and verifies the entry's audit path to its root, recording the inclusion proven
  (index, tree size, root), pending, not included once a tree head signed past the 24-hour
  merge delay still lacks it, or a failed proof. `GET /api/v1/certificates/{id}` and the
  certificate detail show each log's answer (`transparency`). Logs that serve only the
  static CT API are submitted to and their SCTs verified, but their inclusion is not checked.
- Addresses outside the declared segments: `GET /api/v1/discovery/coverage/candidates`
  (`trstctl-cli discovery coverage candidates`) lists the addresses trstctl's own sources
  recorded in the last 30 days — certificate deployment locations, verified endpoints,
  external observations and verification addresses — that no declared segment covers,
  by the same rule sweeps use (excluded segments count as declared). The coverage register
  names them and the console lists them with a one-step segment declaration. Never a
  complete list: an address no source has recorded cannot appear.
- Revocation checks for scanned certificates: with `agent_channel.probe_scanned_certificates`
  on (off by default), a relay's TLS discovery sweep keeps the leaf it finds and up to four
  issuers served after it, each only if it hashes to what the relay reported, and revocation
  health probing checks that certificate's own serial at its CRL distribution points and
  OCSP responders against the served issuer that signed it. `GET /api/v1/certificates/{id}`
  and the certificate detail show those relay-signed answers (`revocation_observations`,
  including whether the CRL lists the serial); probe answers carry `scope` and the endpoint
  list stays one row per endpoint.
- Host recovery after containment: a host profile's containment binding can name a
  `recovery_action`, and `POST /api/v1/connectors/targets/{id}/recovery-check` (CLI
  `connector target recovery-check`, console **Check host recovery readiness**) asks
  the target's enrolled host, in a read-only `endpoint.recovery_check` job enabled with
  `endpoint.contain`, whether its profile pins one and what the listener answers now;
  the signed answer carries SHA-256 digests, never the action's path. A replacement
  preview for a listener containment stopped reads `ready` only after such a check
  shows a recovery action the connector runs while deploying and a listener not
  serving the contained leaf, and creating the replacement otherwise answers 409.
- Managed CA leaf recovery: `POST /api/v1/certificates/managed-ca-recoveries`
  (`trstctl certificates inventory-managed-ca -f leaf.pem`) gives a managed CA leaf a
  version-1 `ca.endentity.issued` mint recorded by serial only its inventory row from
  the public certificate an operator supplies, when the tenant's managed CA signed it
  by its stored certificate and that CA's mint recorded the serial; the leaf is then
  revocable through the inventory workflow.
- Archive legal holds: `POST /api/v1/archives/legal-holds` (object and reason,
  `audit:write`), `DELETE` on `/{id}` and `GET` (CLI `archives legal-holds
  place|release|list`) place and release an S3 legal hold on one archive object under
  the tenant's prefix; the outbox sets or clears it in the bucket and the hold reads
  applied or released only after the bucket reads it back. With the archive under
  Object Lock, a report legal hold also holds the report's object, and the run and
  console show that hold's state.
- S3 Object Lock on the archives trstctl writes: with `object_store.object_lock_mode`
  (`GOVERNANCE` or `COMPLIANCE`) and `object_lock_retention` (at least `24h`), every
  audit archive segment, report artifact and backup set written to the object store
  carries that retention. `trstctl doctor` checks the bucket has Object Lock enabled
  (OBJ-LOCK). The report retention reads a report object's lock first and leaves a
  protected report in place, recording `artifact_removal_deferred_until` on its run
  (a day at a time under a legal hold) and removing it once the lock has ended.
- Tenant custom roles: `PUT /api/v1/access/roles/{name}` defines a role as a named
  subset of the permissions built-in roles grant (only from permissions the caller
  holds), `DELETE` removes one no member holds, and `GET /api/v1/access/roles` lists
  them with `custom: true`; CLI `access roles define|delete` and the People and roles
  console. Assigning a custom role needs every permission it grants. A role resolves
  on every request, so a change applies at once.
- SCIM group-to-role map: `auth.scim.tokens[].group_roles` maps a directory group to a
  built-in or custom role; an unmapped group that is not named for a built-in role is
  still refused, and a group mapped to an undefined custom role is refused by name.
- SCIM token rotation without a restart: a rewritten token file is read again within
  two seconds; a rewrite that cannot be used keeps the last good token.
- Report retention and legal holds: with `audit.report_retention` (or
  `TRSTCTL_AUDIT_REPORT_RETENTION`, at least an hour; off by default), the
  report scheduler queues the removal of every completed run's signed report
  older than the window that no person holds; the outbox removes it from the
  archive directory or the object store and records the run expired only after
  reading the archive back and finding it gone, after which the download
  answers 410 and the run receipt and its SHA-256 remain.
  `POST /api/v1/compliance/report-runs/{id}/legal-hold` (with a reason) and
  `DELETE` on the same path (`trstctl-cli compliance report-runs legal-hold` and
  `release-hold`, `audit:write`) hold a completed report past the window and
  release it; a hold also cancels a removal already queued. The console's
  signed-runs list places and releases holds and shows removed reports.
- Compliance reports in full backups: `--full-backup-dir` captures every
  completed report run's signed report (from `audit.archive_dir` or the archive
  object store) as an encrypted `report-archive` artifact with an index, a full
  restore puts each back where its run's reference says and reads it back
  against its digest, and the restore drill restores them into its isolated
  target and attests the count.
- SPIRE JWT authorities through trstctl: the SPIRE upstream authority plugin
  publishes each SPIRE server's JWT signing key to
  `POST /api/v1/spiffe/upstream-jwt-keys` and returns every unexpired key the
  tenant's SPIRE servers have published, sending the set again when another
  server publishes, so SPIRE servers that share a trust domain through trstctl
  verify each other's JWT-SVIDs. `GET` on the same path (and
  `trstctl-cli spiffe upstream-jwt-keys list`) shows the published keys.
- The host Workload API offers `unix:path:` selectors on macOS: the agent reads
  the caller's executable from its audit token (`LOCAL_PEERTOKEN`, with
  `LOCAL_PEERPID`), and only while the token's pid version still owns the pid,
  so an entry can require a workload's binary path there as it can on Linux.
- Vault-path dynamic credentials: a stock Vault or OpenBao client reads native
  leases at `database/creds/<role>` (username and password), `aws/creds/<role>`
  and `aws/sts/<role>` (an STS session with its assumed-role ARN) and
  `kubernetes/creds/<role>` (a ServiceAccount token), or at
  `<provider>/creds/<role>` when several providers offer the role, and looks
  up, renews (database leases) and revokes them through `sys/leases`; a
  synchronous revoke returns once the provider confirms removal.
- Three secret-sync targets: `webhook` POSTs templated JSON signed with HMAC-SHA256
  over a timestamp and the body (`X-Trstctl-Signature`, `X-Trstctl-Timestamp`), so
  a receiver can refuse a changed or replayed delivery; `aws-parameter-store`
  writes SecureString parameters; `netlify` sets secret environment variables.
- Dynamic-lease rotation: `POST /api/v1/secrets/rotations` with
  `dynamic-lease:<provider>` and `ttl_seconds` replaces the lease an application
  secret publishes with a new lease of that lifetime on a PostgreSQL, MySQL or
  Redis provider, as a durable command: the new lease's credential becomes the
  next secret version once a database session (or Redis AUTH and PING) proves it,
  and the old lease is revoked at the provider. The console's rotation form takes
  the lease TTL.
- `trstctl-kms-wrap`, the signer key store's KMS/HSM wrap adapter, ships in the
  images. With `--kms-provider`/`--kms-key-ref`/`--kms-wrap-command` (Helm
  `externalKMS`), the signer's data keys are wrapped under an AWS KMS key, a
  Cloud KMS CryptoKey, an Azure Key Vault or Managed HSM key, or (in the HSM
  signer image) a PKCS#11 token AES key, and the key store no longer opens
  without that key. Helm's `wrapCommand` defaults to the adapter and
  `adapterConfigSecret` carries its configuration. The signer checks the adapter
  before it serves, so an unreachable or disabled key stops startup with the
  provider's reason.
- Several managed-key providers at once: `managed_keys.providers` lists the
  providers a deployment runs together (for example a PKCS#11 HSM and AWS KMS),
  and the isolated signer builds them all. A key is created under the provider
  its request names, `managed_keys.tenant_providers` pins a tenant to one, and
  every key reports its provider. Actions find a key's provider from its handle.
- Deployment KEK rotation: the operator tenant (`secrets.kek_operator_tenant_id`)
  rotates the deployment KEK, the key behind every credential of a tenant without
  its own key domain, from the local key file onto a key under an operator wrapper
  file or an HSM key the isolated signer holds (console deployment key panel,
  `trstctl-cli platform deployment-kek`, `/api/v1/platform/deployment-kek`). New
  data is wrapped under the new generation at once; the leader re-wraps every
  stored data key, unmigrated tenants' history and the deployment's sealed files
  while requests are served, reads them all back, then retires the previous
  generation. Under an HSM key, stored credentials decrypt only through the
  signer.
- KMIP client registrations: with `protocols.kmip.client_registrations`, one KMIP
  listener serves every tenant's own clients. A tenant registers a client (Transit
  page, `trstctl-cli kmip clients`, `/api/v1/kmip/clients`) and gets a one-time
  enrollment; the client's first request binds its own TLS certificate with that
  username and password, and the certificate then selects the tenant. Each tenant
  sees only its own objects, a new enrollment moves a client to a new certificate,
  and a removed registration is refused at its next request.
- KMIP key pairs: the KMIP listener creates RSA and ECDSA key pairs (Create Key
  Pair), activates them (Activate), signs and verifies with them (Sign, Signature
  Verify), and serves Get Attributes, Get Attribute List and Add, Modify and Delete
  Attribute for names, contact information and `x-` text attributes. Both halves
  start Pre-Active; the private key stays sealed in the server and is not returned
  to Get unless the client created the pair with Extractable set. A revocation for
  key or CA compromise leaves an object Compromised. PyKMIP 0.10 drives the path in
  an opt-in proof.
- Kubernetes CSR approver (opt-in): with `--k8s-csr-approver`, the agent asks
  the issuing CA whether it would issue each pending native
  `CertificateSigningRequest` for a trstctl signer name
  (`POST /api/v1/ca/authorities/{id}/issue/evaluate`, the checks issuance makes,
  without signing; `trstctl-cli ca authorities evaluate-leaf`) and writes
  Approved, or Denied with the CA's reason. A Kubernetes approver still decides
  by default. `deploy/kubernetes/rbac-csr-approver.yaml` carries the grant.
- Agent clock-skew warning: every heartbeat carries the agent's clock and its
  answer carries the control plane's. An agent more than
  `agent_channel.clock_skew_warning` (default 2 minutes) off is named on the
  Agents page and in `GET /api/v1/agents` with the measured drift, counted by
  `trstctl_agents_clock_skewed_total` (alert `TrstctlAgentClockSkew`), and warned
  in the agent's own log. Agents still time renewal by their own clock.
- Relay connector plugins: a module reads its deploy's certificate, fingerprint
  and target (`input.read`) and asks the relay to make its HTTP calls
  (`net.http`). The relay adds the target's credential, splices the private key
  into the body by reference and removes every redeemed value from the reply, so
  the module deploys as the appliance's administrator without holding the
  password or the key. A module that exports `test` answers connector tests under
  a read-only grant (no file writes, HTTP `GET` and `HEAD` only). A reference
  module ships in `plugins/connectors/reference/`.
- Relay failure log: an agent that claims jobs keeps its newest 200 failed
  deploys in a file on its own host (`--deploy-failure-log`, beside `--key` by
  default, mode 0600): when, the job and attempt, the connector and target, the
  step that failed and why, with redeemed values, PEM blocks and the values of
  authorization headers and credential-shaped fields removed.
  `trstctl-agent --show-deploy-failures` prints it. The control plane still
  receives only a closed phrase for a failed deploy.
- Operator-granted agent roles: an operator holding `agents:relay.grant`
  changes an enrolled agent's roles (`POST /api/v1/agents/{id}/roles`,
  `trstctl agents roles grant`, **Change roles** on the Agents page) without
  re-enrolling it. The grant is recorded as an event; the agent's heartbeat asks
  it to renew, the renewal signs exactly the granted roles and records which
  grant it signed, and the agent reconnects with the new certificate. The agent
  list shows the change as pending until a renewal signs it. Roles never come
  from the CSR: a renewal CSR asking for a role the renewal is not signing is
  refused with the role named, on the agent channel and the HTTP renewal
  endpoint.
- Relay egress policy: every connection an agent opens to run a job (appliance
  and API calls, endpoint checks, discovery scans, directory reads, TLS probes)
  refuses link-local addresses, cloud instance metadata, unspecified and
  multicast addresses, and `trstctl-agent --relay-egress-allow` refuses everything
  the operator does not list (CIDRs, addresses, `address:port`). The check runs
  on each request's named destination, so a proxied request is covered, and on
  each dial's resolved address. Windows service installation keeps the
  allowlist across restarts.
- Outcome pages: three pages in the docs (certificate automation and assurance,
  agent and workload identity assurance, and cryptographic risk and migration
  assurance) list each outcome's end-to-end workflow, the evidence every step
  leaves, how strongly each step is proved today (naming the test), the feature
  doc that explains it, and what comes next. The console home gains an
  Outcomes section that routes to each workflow's starting screen.
- Evaluation kit: `trstctl evaluate` runs one certificate journey against an
  endpoint the evaluating team chooses, through the control plane's own API:
  discovery by the control plane's TLS handshake, ownership, issuance on the
  platform CA (with the key generated on the host for an agent-executed target),
  deployment, verification by the command's own TLS handshake, renewal,
  revocation checked over OCSP, and a signed audit export. It writes an
  evidence pack with each step's outcome and whether it was observed or only
  recorded, a pass/fail verdict and the run's limits; a step after a failure is
  skipped, never passed. `--sign` signs the pack with the audit-evidence key
  under its own artifact domain, and `trstctl evaluate verify` checks it
  offline with a pinned audit key set.
- Customer assurance report: `GET /api/v1/reports/assurance` (`trstctl-cli
  reports assurance`) and the `customer_assurance` scheduled report type put a
  tenant's credential assurance into plain sentences in its white-label brand:
  inventory and ownership coverage; expiring, renewed and failed credentials;
  endpoint verification and how changed credentials were verified; incidents
  with their signed evidence; each figure compared with the previous report.
  The signed run carries a self-contained branded HTML rendering. `trstctl-cli
  compliance report-runs verify` checks any saved scheduled report offline
  against the signing key from `GET /api/v1/compliance/report-signing-key`. A
  Provider schedules the report through a tenant template, whose report
  schedules can now announce each run on the customer's channels, and lists and
  downloads a customer's signed runs at
  `/provider/v1/tenants/{id}/assurance-reports`.
- Provider tenant templates: versioned templates of customer tenant objects
  (certificate profiles, the lifecycle policy, CA bindings, connector targets,
  notification channels, member role grants and report schedules). A Provider
  onboards a delegated customer from a version, which registers the customer's
  core tenant when needed and writes each object through the customer's own
  commands; reads back each customer's drift from its version; and rolls a new
  version out across customers after a preview, refused if any customer changed
  since. Each application is an audited Provider authority event.
- Cryptographic risk report: `GET /api/v1/reports/crypto-risk` (CSV through
  `/export`, `trstctl-cli reports crypto-risk`, and the `crypto_risk` scheduled
  report type) lists every weak, distrusted or quantum-vulnerable key with what
  depends on it, the NIST IR 8547 deadline that applies (initial public draft:
  112-bit keys deprecated after 2030, all disallowed after 2035) and the
  crypto-readiness action or recommended next step, in the order to act on. Each
  scheduled run lists what changed since the previous one, read back from the
  archive and signature-checked first.
- MCP evidence tools and structured findings. Six read tools answer posture and
  exposure questions from the served read routes with the agent's own token:
  `posture_findings`, `weak_key_exposure`, `distrust_exposure` (the certificates
  and host trust stores a distrust-list entry affects, each with evidence IDs),
  `assurance_record`, `revocation_status` and `crypto_inventory`. Every MCP tool
  result now carries structured findings (finding ID, evidence IDs, source, time,
  confidence) beside its narrative, under a JSON Schema the tool listing publishes;
  `trstctl-cli mcp serve` advertises it as each tool's output schema and returns
  structured content. Discovery findings filter by `distrust_entry` and
  `key_strength=weak`.
- Agent-to-agent identity over A2A 1.0: a reference pair on the official A2A Go
  SDK (`test/interop/agentframeworks/cmd/a2aagent`). The serving agent's Agent Card
  declares mutual TLS and the delegated-credential header as its security
  requirements and is signed with its trstctl certificate key; the calling agent
  verifies the certificate chain and agent ID, then the card signature with that
  key; every request is authorized by the caller's delegated scope before a task
  exists. The integration suite proves an in-scope task and refuses an
  out-of-scope skill, a borrowed credential, an untrusted CA and a wrong agent.
- MCP authorization with a trstctl agent identity: `GET /agent-keys/{tenant}/{agent}/jwks.json`
  publishes the public keys of an agent's valid broker certificates (a revoked
  certificate's key leaves at once), so the customer's authorization server can
  authenticate the agent with `private_key_jwt` and issue it tokens for an MCP
  server. The reference tool server gains an OAuth resource-server mode (protected
  resource metadata, audience- and scope-checked bearer tokens) and the reference
  agent a client that follows the metadata, authenticates with its identity key,
  and uses the authorization server's token exchange. A lab test proves the flow
  and the revocation against Keycloak; see `docs/guides/mcp-authorization.md`.
- Agent delegation for relying services: each tenant has its own agent issuing
  CA in the signer, published at `GET /api/v1/agent-delegation/issuing-ca` with
  its SPKI SHA-256 so a relying service pins it (another tenant's credentials
  never verify against it), and `GET /api/v1/agent-delegation/credential-status`
  reports `active`, `revoked`, `expired` or `unknown` with the credential's
  SHA-256, so a revoked delegation stops working at a relying service within its
  status window instead of at expiry. CLI: `agent-delegation issuing-ca get`,
  `agent-delegation credential status`. Reference integrations under
  `test/interop/agentframeworks`: an MCP tool server on the MCP Go SDK that honors
  a tool call only within the calling agent's delegated scope, and an agent built
  with the Agent Development Kit for Go (with a scripted model) that calls it with
  its agent identity and delegated credential; the agent delegation integration
  suite runs both against the real signer, and now runs in CI.
- External observers: `POST /api/v1/observers` registers a monitor outside trstctl
  (probectl or any other), and `POST /api/v1/observations` takes what it saw at an
  endpoint — vantage, time, reachability, health, served leaf and chain
  fingerprints. Each report is compared with what trstctl's newest endpoint
  verification expects at that address (`match`, `mismatch`, `unreachable`,
  `unexpected`); a mismatch raises a finding, as does an unhealthy endpoint within
  seven days after the renewal that produced its certificate; a match is
  independent evidence on the certificate's assurance record. Completed renewals
  and connector rollbacks queue signed `rotation.completed` / `rollback.completed`
  events to every enabled observer from the transaction that records them. CLI:
  `observers register|list|update`, `observations record|list`; the observer
  contract is documented in `docs/guides/external-observers.md`.
- Credential assurance records: `GET /api/v1/certificates/{id}/assurance-record`
  (`trstctl certificates assurance-record`) joins one certificate's discovery,
  owner, issuance (CA, the deciding event, profile revision and approval),
  every delivery and verification (served fingerprint, which comparisons ran,
  vantage, the agent or relay and its signed receipt), renewals, revocation and
  the audit entries that name it, each with an evidence ID, and states which
  stages were independently observed, recorded only, or absent. The isolated
  signer signs it under its own artifact domain;
  `trstctl certificates verify-assurance-record` verifies a saved record offline
  against a pinned audit JWK set, and any changed value fails. The response
  includes a Markdown rendering; compliance evidence packs carry the records of
  the certificates whose lifecycle changed in their window; the certificate
  drawer builds and saves the record.
- Lifetime-reduction readiness: `GET /api/v1/certificates/validity-readiness`
  (`trstctl certificates validity-readiness`) evaluates every active certificate
  under the CA/Browser Forum TLS Baseline Requirements 2.3.1 section 6.3.2 steps
  (200 days from 2026-03-15, 100 from 2027-03-15, 47 from 2029-03-15). Each step
  gets a verdict per certificate (`renews`, `at_risk` or `manual`, with reasons)
  from the scheduler's own inventory: what renews it, how its renewal is
  deployed and verified, what holds it, and when the scheduler starts it. A new
  profile field, `public_tls`, says a profile issues publicly trusted TLS server
  certificates; the report flags such a profile whose `max_validity` exceeds a
  step's maximum, or that has none. `.../export` returns CSV naming the BR
  version in its file name and on every row. The console's renewal tab shows the
  report in place of the client-side 47-day simulator, and the profile builder
  sets `public_tls`. The rogue-certificate posture holds a public TLS
  certificate's lifetime to the dated maximum for its issuance date, counted the
  BR way (notBefore through notAfter inclusive).
- The control plane runs the shipped connector families in the WASM sandbox by
  default (`connectors.isolation: wasm`, `TRSTCTL_CONNECTORS_ISOLATION`). The
  binary embeds one digest-pinned first-party connector module; each deploy,
  readback, rollback, takedown, preview, TLS-posture or appliance-key operation
  runs in a fresh wazero instance whose only effects are the sandbox operations
  its grant permits, and whose memory is wiped afterwards. Every family is
  proven to behave identically in and out of the sandbox. The connector catalog
  reports each family's `isolation`. `in_process` keeps the previous behaviour.
- Enrolled host agents and network relays run the shipped connector families in
  the same WASM sandbox by default (`trstctl-agent --connector-isolation`,
  `in_process` to opt out). The relay builds every family through the control
  plane's constructor census, so a relay-built connector is the same connector.
- `POST /api/v1/ai/query` plans questions beyond certificate expiry: certificate
  questions combining expiry windows, expired, status, issuer, key algorithm,
  subject or SAN name, owner and no-owner clauses (as a list or an exact count),
  "who owns" a certificate, crypto assets by algorithm, key size, quantum
  vulnerability or policy, and credential-graph inventories. Each is answered
  exactly from a typed query, beginning with "Interpreted as:"; anything outside
  the grammar is still scoped evidence marked insufficient. The audit record
  (`ai.query.answered` v3) adds the plan kind, its clause kinds and the count.
- Tenant attestors for agent delegation: `POST /api/v1/agent-delegation/attestors`
  (`trstctl-cli agent-delegation attestors register|list`) records a tenant's
  attestor public key and attestation method as an immutable first-writer
  event, provisions it into the isolated signer over its authenticated
  transport and reports `provisioned` only after the signer reads the exact
  binding back. The signer verifies a tenant's attestation evidence only
  against that tenant's attestors, for the registered method and no higher
  class; attestors no longer need operator provisioning on the signer host.
- `/readyz` gains `ssh_krl` (the SSH revocation list can be brought up to the
  event log, when the SSH CA is served) and `audit_read` (audit history can be
  read), so a restarted replica stays out of rotation until its KRL and audit
  reads can be served.
- Continuous audit anchoring at a known cadence (Enterprise audit compliance
  with `protocols.tsa` enabled): whenever a tenant's audit log has grown, the
  leader timestamps the tenant's full audit chain on `audit.anchor_interval`
  (`TRSTCTL_AUDIT_ANCHOR_INTERVAL`, hourly by default, `0s` off) and appends
  the timestamp to the tenant's own log as an `audit.anchored` record.
  `trstctl-cli audit verify --tsa-root ... --anchor-cadence 1h` re-checks every
  anchor inside an unbroken run of exported records, refuses a record that
  entered the chain after an anchor it predates, and requires every record to
  be covered within the cadence; the receipt reports the series as
  `anchor_series`. `GET /api/v1/audit/anchors` (`trstctl-cli audit anchors`,
  Audit console) shows the cadence, state and recent anchors.
- The TSA's certificates are entries of the issuing CA's ledger, so its CRL and
  OCSP responder answer for them. `trstctl-cli protocols tsa certificates
  list|rotate|revoke` (`/api/v1/protocols/tsa/certificates`, Protocols console)
  moves the TSA onto a fresh signer-held key, revoking the outgoing certificate
  with a reason, and revokes a certificate rotated out earlier. Audit exports
  carry the CA's OCSP answer for each TSA certificate their timestamps rely on
  (`validation`), and `trstctl-cli audit verify` checks it against the pinned
  root, refusing every timestamp under a certificate revoked for key or CA
  compromise and those at or after any other revocation; `--tsa-crl` brings a
  fresher CRL and `--require-tsa-revocation` refuses an unchecked certificate.
- Each tenant's anchors are kept in an RFC 6962 anchor log. Audit exports carry
  a head of that log signed with the audit export key (JWS envelopes move to
  schema 2 when they carry it; stream trailers gain `anchor_log`) and an
  inclusion proof for every anchor record they hold; `?anchor_log_from=<size>`
  adds a consistency proof from an earlier head. `trstctl-cli audit verify`
  checks them with `--audit-jwks` and, with `--previous-anchor-log`, proves the
  log only grew since a head kept from an earlier receipt.

- A TrustBundle can also be distributed as an Opaque Secret in each target
  namespace (`spec.target.secret`; outside the agent's namespace this needs
  the opt-in grant in `deploy/kubernetes/rbac-trust-secrets.yaml`) and as a
  ClusterTrustBundle (`spec.target.clusterTrustBundle`) that pods mount
  through a projected volume. The opt-in CSI node plugin in
  `deploy/kubernetes/csi-trust.yaml` (driver `trust.csi.trstctl.com`,
  `trstctl-agent --csi-trust-socket`) serves a TrustBundle to a pod as an
  inline volume and republishes it when it changes. A TrustBundle that cannot
  be distributed is now marked `Ready=False` (reason `DistributionFailed`)
  with the cause, instead of keeping an earlier Ready.
- A TrustBundle can be rolled out from the control plane to several clusters,
  canary first: `POST /api/v1/kubernetes/trust-rollouts` (`trstctl-cli
  kubernetes trust-rollouts start|list|get|pause|resume`, Workloads console).
  Each cluster's agent receives the bundle in the answer to its posture report,
  applies it as a TrustBundle it owns (never one someone else created), and
  distributes it; a cluster reads verified only when its own controller
  reports the bundle distributed with the rollout's SHA-256, and the other
  clusters wait for the canary. The agent ClusterRole gains TrustBundle
  create/update/patch; `--k8s-trust-rollouts=false` keeps rollouts out.
- The Kubernetes agent's controller is event-driven: it lists and watches its
  issuers, trstctl Certificates, TrustBundles, cert-manager
  CertificateRequests, native CertificateSigningRequests and the ConfigMaps it
  distributed, and a work queue converges each object as its event arrives
  (about a second instead of the next poll), with a full re-check every
  `--k8s-resync` (default ten minutes). trstctl Certificates are renewed with a
  new key two thirds of the way through their validity and reissued when their
  spec changes or their Secret is deleted; `status.notBefore`, `notAfter`,
  `renewalTime` and `specHash` record it.
- The Kubernetes Operator manages the control plane's network surface the way
  the Helm chart renders it: a Service (`spec.service`), a default-deny
  NetworkPolicy (`spec.networkPolicy`) and an optional Ingress
  (`spec.ingress`). With `signerMode: isolated` it runs the signer as its own
  pod behind its own Service and a NetworkPolicy that admits only that control
  plane, generates the mutually pinned mTLS pair unless you name your own
  Secrets, renews it a month before it expires, and rolls both pods onto a new
  pair. `spec.signer.authTokenCommand` and `spec.signer.allowCoResidentAuthorizer`
  wire signer authorization as the chart does, and combinations the control
  plane would refuse set the resource `Blocked` with the reason. The operator
  deletes only objects it labels as its own and refuses to take over others.
  Its Role gains delete on Deployments, Secrets, Services, NetworkPolicies and
  Ingresses, and get/create/update/patch on Services, NetworkPolicies and
  Ingresses.

- Certificates can carry a device-bound custody claim the device's TPM signed.
  When an ACME `device-attest-01` attestation certifies a key the TPM generated
  and will not release (`sensitiveDataOrigin`, `fixedTPM`, `fixedParent`), the
  certificate records custody `device` / `device_bound` / `non_exportable` and
  keeps the attestation; `GET /api/v1/certificates/{id}/key-attestation` (console
  download, `trstctl-cli certificates key-attestation`) returns it, and
  `trstctl-cli certificates verify-key-attestation` re-checks it offline against
  TPM roots you choose. The edge sub-CA's TPM lane now refuses an attested key
  the TPM could release.
- A tenant's key domain can be rotated: `POST
  /api/v1/platform/tenant-key-domain/rotate` (console tenant custody panel,
  `trstctl-cli platform tenant-key-domain rotate`) makes a new generation of
  the tenant's domain KEK under the same or another configured wrapper,
  re-wraps every stored data key and the tenant's event history without
  decrypting a payload, and promotes the new generation. Both generations stay
  readable until then, and a failed rotation resumes with the same target.
  Copies taken before a rotation still open with the previous generation.
- A CA can be imported together with the private key it already has: after
  two custodians approve an `import_ca_key` ceremony, `trstctl-cli ca
  authorities key-offer` fetches the signer's one-time import key (HPKE with
  the MLKEM768-P256 hybrid KEM), `wrap-key` seals the PKCS#8 key to it on the
  operator's machine after checking it is the certificate's key, and
  `import-key` has the signer open it, refuse it unless it matches the
  certificate, and hold it under the ceremony's handle with CA-signing
  constraints and dual control. The control plane relays only sealed bytes.
  The console starts the ceremony from **Certificate authorities → Imports**
  and hands over the import request and the commands.
- A signer-backed CA authority's key can be revoked: two custodians approve a
  `revoke_ca` ceremony for the exact authority and reason, and `POST
  /api/v1/ca/authorities/{id}/revoke` (`trstctl-cli ca authorities revoke`, or
  **Certificate authorities → Lifecycle → Revoke a CA key**) executes it. The
  isolated signer refuses every signature with the key from then on, in every
  signer process sharing its keystore; the authority stops issuing; its
  certificate is revoked on a managed parent's CRL; and the response carries
  the signer's own readback. A leaf of a revoked authority is reported as not
  revocable on that authority's CRL, and the periodic CRL refresh skips it.
- The managed-key production-assembly proof has an arm64 profile:
  `make dod-gate-arm64` runs it on a native arm64 host against the release's
  `linux/arm64` control plane and cgo HSM signer, with the same custody substrate
  and entries as the amd64 proof, and CI runs it on GitHub's arm64 runner. The
  proof runner image builds for either architecture from the same pinned inputs,
  and the proof now waits out a queued (202) managed-key receipt the way a client
  does instead of reading it as the key.
- Transit key creation and rotation are facts in the event log: a
  `transit.key.created` or `transit.key.rotated` event names the key, its kind
  and the version, under a fact ID saved with that version's sealed material, and
  is appended only after the material is saved. The versions listing reports each
  version's `fact_id` and whether the log records it; a fact whose append failed,
  and the versions saved before this release, are recorded by a reconcile pass.
- A tenant's key domain can live in the signer under an HSM key: migrate with
  `wrapper_kind: "pkcs11"` and a wrapper ID the control plane lists in
  `secrets.tenant_seal_pkcs11_wrappers`. The signer (the `signer-hsm` image, the
  BYOK license, `--tenant-kek-config`) creates the tenant's domain KEK, keeps it
  wrapped by an AES-256 key the operator provisions on the HSM over PKCS#11, and
  wraps and unwraps the tenant's data keys itself; the database keeps only the
  wrapped KEK and the control plane never holds it. Seal and unseal work as for
  a local wrapper file, a lost HSM key fails only that tenant closed, and the
  console's tenant custody panel offers the choice.
- Transit keys are shared by every replica: each tenant's keyring is a sealed
  row in PostgreSQL, saved before a create or rotate is reported and reloaded
  when a replica lacks a key or version, so a key made on one replica works on
  all of them and after a restart. A keyring an earlier version kept in
  `transit.keyring_dir` is imported at startup, and the file is left in place.
- Authority agreement can observe a KMIP server: an authority entry with a
  `kmip` source block reads object metadata over KMIP 1.4 with a client
  certificate (Locate, Get Attributes, and certificate values; never key
  values). An observation that cannot be complete fails instead of reporting
  part of the server, and `allow_tls12` opts in a server whose TLS stops at 1.2.
- A Cisco ISE destination can name its node and certificate roles
  (`node_hostname`, `certificate_roles`): deploys then import system certificates
  named for their fingerprint and bound to those roles, so the destination rolls
  back by moving the roles to the predecessor and reads back the certificate
  serving them. Cisco is no longer an architecture exception in the relay parity
  program.
- An F5 BIG-IP (a single device), NetScaler, A10 Thunder, PAN-OS firewall or Cisco
  ISE destination can have the appliance generate its own private key:
  `"key_generation": "appliance"` with a pinned network relay. The relay asks the
  appliance for a key and a CSR in an object named for the renewal job, the control
  plane signs the CSR, and the certificate is installed against the appliance's key,
  so no key crosses the relay or the control plane. Custody records the key as
  appliance-generated and appliance-held. Rollback binds a predecessor back with
  its own appliance key without reading it, and a renewal picked up again sends the
  same CSR (for Cisco ISE, which names its requests itself, the relay keeps ISE's
  request ID for the job on the control plane). A PAN-OS destination needs
  `ssl_tls_profile` and `commit_admin`, a Cisco ISE destination its node and roles, an F5
  HA pair keeps control-plane keys, and the destination dialog offers the choice
  where the family supports it (the connector catalog's
  `appliance_key_generation`).

### Security

- EST no longer lets a client choose the address its failed authentication attempts are counted
  against (M1-L1). It read the first `X-Forwarded-For` entry from any peer, so a client could send a
  new address with each attempt; it now counts the connection's peer, or the client a trusted proxy
  forwarded.

- trstctl builds on Go 1.26.11 for GO-2026-6859 (CVE-2026-97054). When a request body passes
  `http.MaxBytesReader`'s limit, Go's net/http before 1.26.11 marks the connection to close
  without synchronization, so an HTTP/1 handler that writes its response headers while another
  goroutine reads the body can crash the server; trstctl bounds request bodies that way, and
  govulncheck reported the flaw as reachable. go.mod's toolchain, the two nested test modules, the
  digest-pinned `golang:1.26.11-bookworm` build images (control plane, NATS, node and PostgreSQL
  trust stages, demo seed, ClusterFuzzLite with its version checks), the deployment census's
  runtime runner and the docs that state the minimum all move to 1.26.11.
- A tenant baseline's connector targets are checked against their module's setup inputs
  (A248-L1). An operator's create and a change set checked a relay module's target
  configuration (A242: required inputs present, typed, a secret input only as a
  reference), but the baseline's target step did not, so a baseline wrote a module target
  with a required input missing or with a secret input holding the secret itself. That
  step now refuses it as the operator's create does, and writes nothing.
- Dynamic database leases are granted an explicit access class (A239-L1). A PostgreSQL,
  MySQL or MongoDB lease used to read its grants from the role's name: any role containing
  "read" was read-only, `readwrite` and `read-write` included, and any other role (`viewer`,
  `reporting`, `analyst`) was granted INSERT, UPDATE and DELETE on every table. A role is now
  `read` or `readwrite` by its `role_access` entry, or by a name that is exactly its class
  (`readonly`, `reader` or `read`; `writer` or `readwrite`); startup refuses any other role,
  and the backend refuses one before any account is created. Migration: give each such role
  its class in `role_access`. The provider catalog lists `role_access` and states the rule.
- MCP certificate writes take the identity lifecycle gate. `issue_certificate` and
  `rotate_certificate` used to issue straight from a named CA authority, outside the
  policy gate and dual control. They now act on a lifecycle identity (`identity_id`,
  with the agent's own CSR for issuance) through its transition route with the agent's
  credentials: a deny-all policy refuses them, and under dual control an issuance is
  proposed (`outcome: proposed`, an approval request, `mcp.tool.proposed`) and runs
  only when the same call is repeated after a distinct approver approved it, while a
  rotation is refused. A call naming `authority_id` is refused. Approval decisions and
  certificate mutations outside the lifecycle gate are never MCP tools. `trstctl-cli
  mcp serve` accepts an `idempotency_key` argument and names the key a proposed write
  is bound to.
- The signer's attestation verifier checks the key ID inside attestation
  evidence as a single path segment and reads the key through a directory
  handle. Before, the key ID was joined into a file path unchecked, so evidence
  could name another public key file on the signer's floor as its attestor.
- Every image now ships one trust store: the pinned, checksum-verified Alpine
  `ca-certificates-bundle-20261020` filtered at build time by the shipped
  distrust list (`internal/crypto/trust/distrust.json`), which leaves exactly
  Mozilla's 118 websites roots. The list names the three emSign roots Mozilla
  removed on 2026-10-20 and, by public key, the eight eMudhra intermediate CAs
  whose P-384 private keys are small integers anyone can recover; matching by
  key also catches their AAA Certificate Services cross-signs. The control
  plane, signer-hsm and agent-pkcs11 images previously trusted the Debian or
  distroless bundle (150 and 142 roots, including those emSign roots and AAA
  Certificate Services, 42 and 49 roots Mozilla no longer trusts for websites,
  and 10 and 25 it does that were missing); the Alpine-based images trusted
  the three removed roots. Go 1.26.10, which trstctl has built on since
  2026-10-21, already rejects any chain through the eight intermediates in
  trstctl's own binaries; builds and images from before 2026-10-21 (v0.6.0
  included) do not, and nothing before this change protected non-Go software
  in the images or guarded against another weak key under the same roots.
  `trstctl-trustbundle` (filter, probe, list) is the build-stage tool; the
  Node images read the system store (`NODE_OPTIONS=--use-openssl-ca`).
- Every outbound TLS client now checks a runtime distrust list after normal
  verification, on resumed sessions too: a verified chain through a distrusted
  root, intermediate or key (the three emSign roots and the eight eMudhra
  intermediates by SPKI, so their cross-signs are caught) fails the handshake
  with the entry named, while a server that also presents a clean path still
  connects, as Go's own distrust list behaves. The check lives in the shared
  transport builders (`internal/netsec`, the egress guard), on the process
  default transport every binary installs at startup, and on an
  operator-pinned external CA root as well; operators add entries with
  `trust.distrust_file` for sites that cannot take a release the day a CA is
  distrusted, and the shipped entries cannot be removed.
- Ambient outbound clients that trusted the system store directly (the
  identity-provider metadata and JWKS client, secret-sync pushers,
  dynamic-secret backends, cloud token and discovery clients, AWS IAM, connector
  HTTP operations, DNS-01 providers, telemetry, the OTLP exporter, the model
  client, the CLI without a CA file, the operator's and the agent's Kubernetes
  clients) now come from the `internal/netsec` builders, so the runtime distrust
  check covers them, each at the timeout it had before; none gains the SSRF
  guard, because their endpoints are operator-configured and may legitimately
  be private. The architecture linter (SEC-005) also refuses an `http.Transport`
  or `tls.Config` literal built outside `internal/netsec`, `internal/egress` and
  the crypto boundary.
- `make trust-audit` builds every image and compares the roots Go loads from
  each (Go's own Linux rule, `SSL_CERT_*` included) with Mozilla's current
  websites trust list from CCADB and the shipped distrust list; a root Mozilla
  does not trust for websites, a distrusted certificate or key, or a redirected
  store fails and names the image and the root. It runs daily
  (`.github/workflows/trust-audit.yml`) and gates the release workflow from the
  `release-evidence` job, which every publishing job needs;
  `trstctl-trustbundle audit` is the step behind it. Ordinary builds and pull
  requests still use no network.
- Weak-key detection (`internal/crypto/weakkey`, modeled on badkeys): an
  elliptic-curve key whose private scalar is small (|k| up to 2^24 + 2^16, by
  baby-step giant-step; the eMudhra intermediates' were 4 to 237), RSA moduli
  with small factors, close primes, the ROCA structure, impossible exponents,
  a prime shared with another key in the same inventory (batch GCD), and keys
  on operator-supplied blocklists such as Debian's 2008 list
  (`TRSTCTL_TRUST_WEAK_KEY_BLOCKLIST_FILES`; trstctl ships none, the Debian list
  is GPL-3). Private keys an agent finds are now named for every RSA size and
  curve (an RSA-1024 key used to have no algorithm at all) and reported weak
  with the reason. The distrust list carries each entry's subject key
  identifier, so a leaf under one of the eight intermediates is found from its
  authority key identifier. See docs/security/weak-keys.md.
- Every certificate trstctl discovers is rated while its bytes are at hand:
  agents rate what they find (files, Kubernetes, PKCS#11, Windows and every
  trust store), cloud discovery rates what the provider returns, and the CT
  monitor rates the hits it keeps. The verdict (weak key with reasons;
  distrusted certificate or issuer, naming the entry) travels as finding
  metadata and raises the risk to 85 or 95. The control plane re-rates every
  agent report against its own distrust list and replaces any distrust claim
  in it, so a host trust store holding emSign ECC Root CA - G3 is a finding
  even from an older agent.
- A relay's network scan rates the whole served chain, not only the leaf, and
  reports it as hashes and closed check codes (the scan protocol admits no
  certificate bytes or free text); the control plane applies its own distrust
  list and words the reasons.
- CBOM certificate-key assets are rated from the served leaf and chain: a key
  with a structural weakness, or one whose certificate depends on a
  distrust-list entry, is weak and out of policy whatever its size, with the
  reason and the migration plan that replaces it.
- The CA key ceremony refuses weak keys and proves possession. The signer
  refuses a weak key it generates, mints or imports, and an HSM or KMS key
  that fails is zeroized (closed code `provider_key_weak`). No weak key is
  certified as a CA, and imports and cross-signs refuse a CA certificate that
  is weak or on the distrust list. A signer-held key signs a fresh challenge,
  verified against the exact public key going into the certificate, before it
  is certified as an intermediate or bound to an import. The managed-key
  custody probe now carries a fresh nonce.
- The leader runs batch GCD over each tenant's RSA public keys every six hours
  (CA authorities, inventory certificates and the keys agents, cloud discovery
  and the CT monitor now report) and records a `weak-key` finding wherever a key
  shares a prime with another, as a discovery run under the product-owned
  `weak-key-audit:batch-gcd` source. Reported RSA keys are also rated against
  the operator's blocklists, which only the control plane holds.
- A distrusted root an agent finds in a host trust store can be removed through
  trust distribution (`POST /api/v1/discovery/findings/{id}/remove-distrusted-root`,
  `trstctl-cli discovery findings remove-distrusted-root`, or **Remove from host
  trust store** in the console's finding detail). The exact host agent
  reads the file, removes it only when it holds just that root and the agent's own
  distrust list names it, and reports a signed result onto the receipt; bundles,
  other certificates and paths outside the host profile are refused and left
  alone. Agents take an operator distrust list with `--distrust-file`.
- An offline root's import can carry `possession_signature`, the root's
  signature over the import ceremony's challenge, made on the offline system
  with the OpenSSL commands in the key ceremony runbook (the console prints
  them). Every CA creation and import now records how possession of the key
  was established (`self_signature`, `signer_challenge`, `offline_signature`
  or `not_proven`) in its response and its creation event.

### Fixed

- ACME S/MIME orders (P15): a CSR that names the mailbox as its common name, as stock S/MIME
  clients do, is issued; the protocol profile gate took that common name for a DNS name and
  refused the order. Proven with a stock RFC 8823 client library through a real mail server, and
  a stock mail client verifying a message signed with the certificate.

- A host destination whose key the control plane generates (no `"executor": "agent"`) deploys again. Since a host
  destination must name its agent in `required_agent_id`, the credential grant still asked for the key-custody marker
  as well, so the assigned agent was refused the sealed deploy ("credential redemption was not granted") and every such
  deploy failed. The grant now binds the work to the agent the target's reviewed configuration names, whichever side
  generates the key; a target naming another agent, or none, is still refused.

- The Windows agent MSI installs again on current Windows releases: Windows Installer applied the service's
  restart-on-failure actions without the start right a restart action needs, so the install failed with error 1939
  and rolled back. The agent's service now sets its restart policy (30 seconds, 60 seconds, then 5 minutes) on itself
  whenever it starts, and `--service=install` sets it at registration; the MSI keeps only the setting that counts an
  error exit as a failure.

- `gcp-iam` revocation deletes only keys of the bound service account: a reference naming any other resource, or
  another account's key, is refused instead of becoming a DELETE path (A240).

- Repository secret scans of a `clone_url` now run with the real scanner: the clone lands in a temporary directory
  outside the configured scan roots, which the scanner refused, so every cloned repository scan failed; that one
  directory is now the clone scan's root. A cloned repository's finding also keeps one identity across scans (its
  fingerprint no longer names the temporary directory), so a rescan sees the same finding instead of adding another.

- CBOM import refused ordinary image scans: the shared 1 MiB mutation body limit applied before the import's
  own limit, and an import held at most 5,000 components, while the real cbomkit-theia's CBOM for a small Alpine
  image is about 6 MiB and 8,000 components. An import now reads its own body (up to 32 MiB) and holds up to
  50,000 components.
- The code-signing approval docs described the legacy identities approval route and a new Idempotency-Key;
  the served flow is `POST /api/v1/approval-requests/{id}/approvals` (or `/denials`) and repeating the same
  request with the same key, which consumes the approval once.
- The RFC 2136 DNS provider's TSIG-signed updates are accepted by DNS servers: the signature now covers
  every TSIG variable RFC 8945 lists, including Other Len, which was left out, so a standards server (BIND,
  Knot, PowerDNS, miekg/dns) refused every signed update as "bad signature" and DNS-01 through RFC 2136
  never published.
- A SPIRE server whose upstream authority is the trstctl plugin no longer stops
  at startup when trstctl does not serve JWT key publication (an older trstctl
  answers 404): the plugin reports publication as unsupported, so SPIRE logs a
  warning, keeps its JWT keys in its own bundle and starts; the next JWT key
  rotation publishes again.
- The SPIRE upstream authority docs said the plugin's token needs `certs:issue`;
  the intermediate CSR route needs `issuers:write`, and it signs only under an
  approved ceremony for each CSR, which the docs now say.
- Moving a tenant into its own key domain, or rotating that domain, now re-wraps
  the tenant's shared transit keyring with its other secrets. The keyring stayed
  under the previous key, so a replica that started afterwards, or any replica
  after a restart, could not open it, and the tenant's transit keys stopped
  working.
- A CA authority's leaf route (`POST /api/v1/ca/authorities/{id}/issue`) now
  refuses a subject key the tenant recorded as compromised (422, naming the
  compromise), as every other certifying path already did; it signed one before.
- A staged agent upgrade's soak window now ends when its reason says. Recording
  the soak cleared the ring's dispatch, so the next sweep sent the ring's agents
  a second round of upgrade jobs and the window started over; a campaign that
  dispatches nothing could move its window forward on a later sweep. Either way
  the soak might never end.
- The Kubernetes agent no longer stops its controller pass on a cluster without
  cert-manager (native CSRs and TrustBundles were never reconciled there), no
  longer rewrites every TrustBundle ConfigMap and status on every pass, keeps a
  ConfigMap's other keys when it updates the bundle, and renews trstctl
  Certificates, which it used to issue once and leave to expire.
- The Kubernetes Operator could not create a control plane on a real cluster:
  its owner references lacked the `uid` the API server requires. Its pods now
  also run as the image's non-root user with that group owning mounted
  Secrets, so the 0440 KEK and signer-authorization files are readable.
  Upgrading the operator rolls each managed control plane once onto the
  corrected pod template.
- The first issuance of an identity bound to a host-executed destination never
  completed in a tenant that had not yet issued a certificate from the platform
  CA: after handing the work to the host agent, the issuance command tried to
  refresh a CRL the tenant could not have yet and retried forever. The CRL step
  now runs only when the command itself issued a certificate.
- Rogue certificate detection flagged every ECDSA certificate as a weak key
  (risk 85) and never an RSA-1024 one: it read only the bare algorithm name, so
  "ecdsa" matched "dsa". It now rates the certificate itself when trstctl holds
  it (key, signature hash, structural weaknesses), else the verdict discovery
  recorded, else the recorded algorithm name, and gives the reasons in
  `weak_key_reasons`. A certificate that is, or chains to, a CA or key on the
  distrust list is a new critical `distrusted_issuer` finding naming the entry
  and how it matched.
- SSH fleet and Workloads no longer label every discovered raw host key as
  outside SSH CA trust. The inventory reports observed key locations and
  standing grants; proving CA posture requires sshd trust and served-certificate
  evidence. The unsupported `under_ca` and `hosts_not_under_ca` fields were
  removed from the API and generated clients.
- Raw SSH revocations now survive control-plane restarts and reach other replicas
  through the event-backed KRL. Raw SSH mutations use the API guard, including
  tenant admission, permissions, rate limits, ABAC and idempotent replay.
- Direct SSH user certificate issuance requires an explicit principal allowlist;
  host certificates reject user options. SSH issuance events record the caller,
  principal names and validity window.
- Restarting the control plane during an incident fleet re-issuance no longer
  lets the legacy batch worker revoke a wave's certificates before their
  replacements exist; revocation always waits for a verified successor.
- The built-in `viewer` and `mcp` roles no longer include `secrets:read`, which
  revealed application secret values in plaintext. Grant it deliberately through
  `operator`, `cli`, `admin` or a custom role.
- Roles set on a tenant member now decide that person's session. Before, sign-in
  roles from a tenant mapping or `default_roles` were added to them, so a member
  set to `viewer` could still hold `admin`. A member record without roles keeps
  the sign-in roles.
- Only a caller that holds every permission can grant the `admin` role. An
  `operator` or a role-provisioning token can still assign every other role.
- An API token minted for another subject can no longer approve or deny on that
  subject's behalf; every approval route refuses it. Approvals now count people,
  not token names.
- API tokens minted through the API expire after 90 days by default and cannot be
  given a longer expiry (`auth.api_tokens.max_lifetime`; `0` opts out).
- Agent renewal over HTTP now refuses revoked certificates and offboarded agents,
  as the agent channel already did; before, one renewal call undid a revocation.
- Agent renewal, over HTTP and over the agent channel, can no longer change which
  agent a certificate names; a CSR naming another agent is refused with 403.
- The workload co-sign listener requires pinned mutual TLS on `host:port`, creates
  `unix:` sockets owner-only with a peer uid check, and bounds request size and
  concurrency. Before, any process that reached it could obtain co-signatures.
- `/metrics` no longer names tenants: the outbox dead-letter, delivery-timeout and
  circuit metrics are labeled by destination only, and the metrics registry now
  refuses any tenant label.
- `ca.ceremony_min_approvals` (`TRSTCTL_CA_CEREMONY_MIN_APPROVALS`) sets the
  fewest custodian approvals a CA key ceremony may require; requests can raise
  the threshold but not lower it, and `regulated` governance requires at least 2.
- Notification delivery details open at the heading, keeping the outcome visible
  before operators tab through the dialog.
- Certificate replacement explains when a matching identity is already renewing
  and links to its lifecycle evidence without allowing concurrent replacement.
- Certificate detail drawers keep populated lifecycle evidence and metadata
  inside narrow and intermediate-width viewports.
- Signer help identifies PCAS succession as core and the license option as the
  gate for Enterprise managed-key providers.
- SAML sign-in started from the console resumes the requested local page,
  including query filters and fragments. A signed, expiring context binds the
  destination to that login attempt; IdP-initiated login keeps its configured default.
- The console offers each configured browser sign-in method, including SAML-only
  and LDAP-only deployments. Directory sign-in has accessible credential fields,
  safe retry guidance, password clearing and verified-session navigation.
- SP-initiated SAML browser login now sends its secure correlation cookies on
  the identity provider's cross-site POST. State, request-ID and signature checks
  remain required; OIDC and authenticated session cookie policies are unchanged.

### Changed

- License: the core's Additional Use Grant now defines hosted and managed services, lets a provider
  do one-off project work in a customer's own deployment, counts affiliates and staff contractors as
  the licensee, narrows the competing-product clause, and requires keeping the trstctl name and
  attribution visible. Versions published earlier keep the grant they were published with. A
  plain-language license FAQ is in the docs.
- Kubernetes, GCP and Azure machine-login tokens are single-use, like OIDC and JWT tokens and like
  the token exchange (A238-L8). A projected service-account token used to log in again until it
  expired, so anyone who copied one could open sessions with it. Each token now logs in once on any
  replica; a method whose clients present a platform-managed token more than once sets
  `allow_token_reuse: true` (the CSI secrets driver's `kubernetes` method needs it). The login
  preview and `GET /api/v1/secrets/auth-methods` say which.
- The stale NHI posture no longer calls an API token unused when trstctl has no usage telemetry for it: before
  this release every token older than 90 days read as unused.
- An audit export or search that is an unbroken run of records selected only
  by time or sequence now carries the hashes its records have in the tenant's
  full audit chain, and its `prev_hash` is that chain's head just before its
  first record (before, every selection was re-hashed from the archived
  prefix). Content-filtered selections are unchanged. Search responses now
  include `prev_hash`, and record-stream trailers mark a full-chain export with
  `"chain": "tenant"`. Saved exports from either rule verify as before.
- CA-agnostic outbound issuance (F4) is now listed as served. Its last
  residual, the Kubernetes CSR and TrustBundle posture routes, already served
  the authenticated reports the cluster agents send and is proven by the
  definition-of-done census against a real kind cluster; the catalog,
  requirements and limitations had kept calling those routes descriptor-only.
- A `k8s_ingress_gateway` discovery source can be bound to the host-role agent
  running in the cluster (`cluster_agent_id`, `owner_id`, optional
  `verify_address`). Each run then keeps a `k8s_secret` destination and a
  certificate identity per TLS block and queues the first issuance to that agent,
  which generates the key inside the cluster, sends only a CSR, writes the TLS
  Secret and reads it back; the certificate records `key_storage=kubernetes_secret`.
  Resources report `delivery_queued`, then `delivered`, or `not_delivered` with the
  agent's own reason while a failed attempt is retried. A source without an agent
  still reports each resource `not_delivered` with the reason. A `k8s_secret`
  destination saved without `executor=agent` is refused.
- The outbound clients that used Go's default client with no timeout at all
  (secret-sync pushers, dynamic-secret backends, the ACM, Certificate Manager
  and Key Vault discovery clients, the Azure and GCP token clients, AWS IAM,
  connector HTTP operations, the nine DNS-01 providers and the CLI connector
  client) now time out after 30 seconds; a request that needs longer fails
  instead of hanging. Callers that inject their own client are unaffected.
- Tenant SAML, LDAP and SCIM now require Enterprise SSO, included in Enterprise
  and inherited by Provider. Their implementations live under `ee/enterpriseauth`;
  OIDC, shared session persistence and tenant authorization stay core. Configuring
  these tenant methods without the attached licensed implementation refuses startup.

- PCAS operator/security guides now live in the public documentation. Edition
  references identify PCAS, AGID, XREC, VDEC, PQC and remediation as core;
  obsolete family-specific gate targets are replaced by direct integration and
  conformance commands while the core/EE boundary gate remains. The smaller
  commercial tree measured 70.7% coverage; its enforced floor rises from 65%
  to 70%. Patent claim traceability remains under `ee/docs/`.

- Managed tenant provisioning saves the reviewed request and its original
  idempotency key before sending it. Operators can recover an uncertain result
  from the same account after reloading or reopening the browser, without
  generating a conflicting registration request. The server checks the reviewed
  tenant and operator before creation or replay so another tab's account switch
  cannot silently change the account used for provisioning.

- Managed tenant provisioning now accepts its existing provider metadata under
  the required event privacy policy, while retaining closed field validation.

- Authority agreement reports now show only the authenticated tenant's
  authorities, counts, resolution metrics and collection status. Reconciliation
  replay keeps witness ownership separate across tenants and rejects conflicting
  event tenants before changing projection state.

- Core PQC migration and rollback remain available after a commercial license
  expires, with tenant authorization and idempotency checks preserved. Edition
  disclosures now place PQC in Free Core and the operator guide reflects the
  current rehearsal command.

- Remediation is part of Core: incident and guided remediation routes now mount
  without a commercial license in both normal and Core-only builds. Tenant
  isolation, RBAC, policy, idempotency and outbox requirements are unchanged. The
  credential-compromise workflow library moved from `ee/incident` to
  `internal/incident` under BUSL-1.1.

- **Licensing.** The core moved from the Mozilla Public License 2.0 to the
  Business Source License 1.1 (Licensor certctl LLC): production use is permitted
  under the Additional Use Grant, the Free tier needs no signed license, and each
  release converts to MPL-2.0 four years after it is published. `clients/` stays
  MPL-2.0; `ee/` stays proprietary. Every core file's SPDX header reads
  `BUSL-1.1`.
- **The patent-pending families and PQC are core.** PCAS (`internal/succession`,
  `internal/translog`, `internal/rpverify`), AGID (`internal/agentid`), XREC
  (`internal/reconcile`), VDEC (`internal/decommission`) and PQC (`internal/pqc`,
  `internal/pqcruntime`, `internal/pqcmigration`, `internal/kmip`) moved out of
  `ee/` and attach in every build through `cmd/*/attach_families.go`; the
  `pcas`, `agent-delegation`, `reconcile`, `vdec` and `pqc` license features are
  gone (a license file that still names them parses and grants nothing extra).
- **Migration ledger.** The `-- SPDX-License-Identifier:` line is outside a shipped
  migration's content digest; a ledger row recorded by an earlier binary under the
  previous identifier is recognized and re-stamped with `checksum_adopted_at`.
- **The Terraform provider is its own MPL-2.0 module.** `terraform-provider-trstctl`
  moved from `cmd/terraform-provider-trstctl` and `internal/terraformprovider` to
  `clients/terraform` (module `trstctl.com/terraform-provider`), licensed MPL-2.0
  with the rest of `clients/`. Its module path sits outside `trstctl.com/trstctl`,
  so the compiler refuses any import of the control plane's `internal/` packages:
  the provider reaches trstctl only through the served REST API. `make build`,
  `make reproducible-check`, `make sdk-test` and the registry release script
  build and test it from that directory, and the Terraform SDK modules are no
  longer requirements of the core module.
- **No published pricing.** Reference list prices and wholesale bands are gone
  from the docs (`docs/pricing.md` is removed), the README and the editions API:
  `GET /api/v1/editions` no longer serves `reference_price_bands`, and
  `pricing_posture` is now `commercial_posture`, stating that Enterprise and
  Provider terms are agreed per customer and not yet published. The console's
  editions panel no longer renders a price table.

## [0.6.3] - 2026-09-19

Tagged after 0.7.0 on the same line of development; it carries one change.

### Changed
- CI: CodeQL is scoped to shipped product code, so analysis time goes to the
  binaries that ship rather than to tooling and fixtures.

## [0.7.0] - 2026-09-16

### Fixed
- Provider authority and customer service state are enforced on every
  provider-plane mutation, and completed credential requests are recovered
  rather than dropped.
- Live tenant policy is isolated per tenant, and the lifecycle surfaces show
  the actual authority that governs each identity.
- Tenant authority is preserved through governed lifecycle recovery.
- Local bootstrap token creation is recorded through events, so the audit
  trail covers it like every other issuance.
- Retained-batch subscription callbacks are joined before cleanup in the
  events tests, removing a teardown race.

### Changed
- The console is English-only (R07); the locale plumbing that shipped no
  translations is gone.
- Documentation explains the first-member role provisioning handoff.

## [0.6.0] - 2026-09-15

The development milestone that closed the summer hardening train: 1,762
commits since 0.5.4. The last weeks before the tag repaired the verified
lifecycle and operator journeys, bounded retained-history transport and
decoding, activated existing SSH trust on retry with effective-config
validation, retained verified PostgreSQL archives in server test shards,
made the lint tool distinguish fresh upsert keys from exclusive locks, and
refused repeat signing when retained issuance needs a rebuild. The dated
entries below are the train's own log.

### Bundled PostgreSQL authenticates executable bytes before startup (2026-09-09)

- The evaluation database verifies its independent committed archive checksum
  before extraction or execution, including on a cold download. Maven's checksum
  sidecar remains an additional transport check.
- Each start extracts authenticated bytes into a fresh private directory. The
  archive cache includes platform, version and digest; stale extracted binaries
  cannot survive a pin change. Existing database data and legacy caches remain
  intact.
- Rooted extraction rejects unsafe paths, links and file types, and enforces
  expansion limits.
  Complete archives and executable trees are published atomically. Startup errors
  preserve their original cause and never stop an unproven existing server.
- Regression tests call the actual startup wrapper and check executable markers,
  tampered archives, extraction limits and concurrent publication. Legacy test
  and developer-tool loaders remain outside this served-path provenance claim.

### Lint tool failures cannot qualify unchecked source (2026-09-08)

- Formatting and architecture lint stop on failed prerequisites, including an
  unavailable temporary file or a failed analyzer build.
- The EE lint gate validates the full scanner report and exit status, requires
  every configured linter, retains diagnostics and refuses malformed results.
  It reports potential baseline reductions without editing the baseline file.
- The EE scanner also bounds output while running and stops its process group
  on timeout or cancellation. A scanner that leaves children behind fails.
- Regression tests inject tool failures into the actual Make recipes and verify
  that incomplete checks fail before later work can hide them.

### Dark-segment enrollment relay failover is observable and stock-ACME-safe (A4, 2026-08-12)

- **A relay returned an ACME directory whose absolute URLs named the control
  plane.** A stock client followed the second URL directly, so the claimed dark-
  segment path failed even though isolated `/directory` and `/acme/*` proxy tests
  passed. Relays now require one stable `--enroll-proxy-public-url` and preserve
  that HTTP authority while the socket still dials only the configured control-
  plane endpoint. Signed request bodies and protocol responses remain byte-for-
  byte pass-through, and the proxy still attaches no agent credential.
- **Control-plane endpoint failover was mistaken for relay redundancy.** Each
  certificate-bound network relay now reports its operator-named
  `--enroll-proxy-segment`, public URL, verified/unavailable/unverified upstream counts,
  process-lifetime forwarded/refused/failure counters, and last forward/failover
  times on its authenticated heartbeat. The immutable event stream rebuilds the
  tenant projection; `GET /api/v1/agents`, generated SDKs, and the Protocols
  console show the exact per-segment relay rows and redundancy count.
- A configured endpoint starts **unverified**, not healthy. Only a completed
  response proves health; retry-cooldown expiry merely permits another probe.
  A real HTTP 502 from the control plane remains the client's response, while
  only an out-of-band transport failure changes upstreams.
- The assembled acceptance starts two relay subprocesses behind one segment URL.
  A stock `golang.org/x/crypto/acme` client registers through the primary, the
  primary process dies, and the same client completes a real signer-backed order
  through the secondary. Its transport refuses the control-plane authority and
  records zero attempted direct routes.

### The repository has an intake path and a code of conduct (2026-08-02)
- **README.md and CONTRIBUTING.md told readers to open an issue; nothing was
  behind that invitation.** `.github/ISSUE_TEMPLATE/` now carries a bug report
  and a feature request as GitHub issue forms, each requiring only what a
  maintainer needs to reproduce or judge the report — version/commit, what
  happened versus expected, and steps for a bug; the problem, the proposal, and
  whether it lands in core or `ee/` for a feature.
- **A vulnerability could be filed as a public issue in one click.** SECURITY.md
  says not to; nothing enforced it at the point of filing. Blank issues are now
  disabled and a contact link routes a would-be reporter to SECURITY.md before
  the new-issue form, with a second link to `docs/limitations.md` so a
  not-yet-served subsystem is not reported as a defect.
- **CODE_OF_CONDUCT.md adopts the Contributor Covenant 2.1 verbatim**, with the
  enforcement address taken from the one SECURITY.md already publishes rather
  than a second address that could drift. A guard in `docs/issue_intake_test.go`
  pins all of it, including that the two addresses stay the same.

### Broker-issued agent credentials can be task-scoped (B-7, 2026-07-26)
- **Only the chain-bound delegation path could bind a credential to one
  authorized task.** The broker's single-hop path — the one an AI/MCP agent
  actually uses — could not carry an AGID-05 task envelope at all, so a broker
  badge had standing scope and nothing narrower. `POST
  /api/v1/broker/agent-identities` now accepts `task_envelope_base64` and
  returns the `task_envelope_digest` the credential binds, which the caller
  can recompute to confirm the scope it authorized.
- **An envelope the build cannot verify is refused, not ignored.** This is the
  rule that makes the binding worth anything: silently issuing an *unscoped*
  credential in place of the scoped one a caller asked for is precisely the
  outcome an attacker would engineer, so a Community / core-only build (which
  attaches no gate) rejects the request. Requests carrying no envelope are the
  ordinary single-hop badge, untouched — INV-A10 zero removal holds.
- **The gate reuses the delegation gate's own verification**
  (`taskenv.VerifySignatureAndExpiry`): requester signature over the canonical
  bytes, resolved through an operator-provisioned trust store on the signer
  floor that the caller cannot inject into, plus the expiry window. The bound
  digest is computed from the envelope that just passed, so a substituted
  envelope cannot be bound in place of the signed one, and the binding is
  emitted into the audit chain (AN-2) rather than living only in a response.

### A migration can be reviewed before it runs (B-3, 2026-07-26)
- **You could start a fleet-wide re-issuance; you could not look at it first.**
  `POST /api/v1/pqc/migrations/plan` (and `trstctl-cli migration plan`,
  Enterprise PQC) previews the plan — which assets would be re-issued and to
  what, which TLS findings would be rolled out, and **the residuals it will
  not touch** — with no run id, no outbox row, and no event. The residual list
  is the half that makes the preview honest: a plan that only showed what it
  *will* do would overstate coverage.
- **The preview cannot lie about the migration.** It calls the same
  `BuildPlan` the start path calls, over the same CBOM assets, so a divergence
  between preview and execution would have to be a divergence inside the plan
  builder itself — not two implementations drifting apart.
- The licensed READ seam grew the response writers it was missing
  (`WriteJSON`/`WriteError`/`WriteProblemUnauthorized` beside the existing
  `Tenant`), so a licensed GET renders errors in exactly the core's
  problem+json shape instead of inventing its own.

### Signing history is verifiable after the fact (B-4, 2026-07-26)
- **Code signing served the two mutations and nothing that answered
  afterward.** You could sign with a managed key or keylessly, but nothing
  told you which identities had signed or whether the transparency-log entry
  actually landed. `GET /api/v1/code-signing/identities` (and `trstctl-cli
  code-signing identities`) lists recent operations with their identity kind
  and each one's transparency state — `verified`, `pending`, `failed` with its
  reason, or `not-published` — plus the two counts a reviewer asks for first.
- **Verification is not a second source of truth.** Rekor publication rides
  the outbox, and the handler refuses to acknowledge an entry whose signed
  receipt does not verify — so a delivered outbox row *is* a verified entry,
  and the view reads that state rather than a parallel flag that could drift
  from it. The query reads no sealed command bytes, so the plaintext identity
  assertion and artifact digest never leave the signer boundary through it.

### The SSH estate outside the CA is readable (B-2, 2026-07-26)
- **The SSH surface covered the credentials trstctl issues and nothing about
  the ones it does not.** CA status, trust rollouts, attested user certs and
  revocation were all served, while discovered SSH keys sat in the inventory
  with no view answering the operator's actual question: which hosts still
  have standing key-based access that certificate rotation cannot reach.
  `GET /api/v1/ssh/fleet` (and `trstctl-cli ssh fleet`) rolls those keys up
  per host — key count, standing-access count, orphaned count, key types,
  sources, observation window — ordered worst host first, so the hosts most
  needing to come under the CA sort to the top.
- **The not-under-CA claim is structural, not inferred.** Every row behind the
  view is a raw key, because a certificate minted by the SSH CA is never
  stored as an `ssh_key`; each host therefore carries `under_ca: false`
  explicitly, and the response repeats the count so a dashboard does not have
  to restate the invariant. Metadata only — fingerprints, types, locations —
  never private key material.

### The connector catalog reports its sandbox contract (B-6, 2026-07-26)
- **The catalog described what a connector deploys, never what it may do.**
  An operator authorizing a privileged deployment could not see the two facts
  that matter: what the connector is permitted to touch, and what happens on a
  redelivery. Each catalog row now carries `native` (this build has a native
  implementation), `capabilities` (the declared sandbox grant — `fs.read`,
  `fs.write`, `net.dial`, `process.exec`, sorted), and `replay_safety`
  (`reconciled` when the receiver converges on retry, otherwise
  `at-most-once`).
- **Read from the live registry, not written beside the description**, so the
  catalog cannot drift into claiming a capability the process would not
  enforce. Reporting never constructs a connector. A connector this build does
  not implement natively reports no capabilities and the conservative
  at-most-once contract, and a control plane assembled with no registry claims
  nothing at all.

### The running system is readable from the console (B-5, 2026-07-26)
- **`/admin/system` showed posture, not the system.** It rendered what the
  product *claims* — edition, support tier, scale plan — but not the readout
  an operator wants when something looks wrong. That answer existed only on
  `/healthz` and `/readyz`, which are unauthenticated infrastructure probes
  shaped for a load balancer. `GET /api/v1/platform/system` (and
  `trstctl-cli platform system`) reports the build version/commit/date, the Go
  toolchain, process start time and uptime, the **live** AN-4 signer topology
  (`child`/`external`/`none` — what is actually attached, not what the config
  intended), whether the FIPS module is routing `crypto/*`, and per-dependency
  reachability for the database, event log, and signer.
- **It reuses the same probes as `/readyz`**, so the console and the load
  balancer can never disagree about whether the spine is up — the failure mode
  that makes an operator distrust both. Probes are bounded at 3s so a hung
  dependency degrades this endpoint instead of hanging the caller, and the
  readout carries no addresses, DSNs, or configuration values: a component is
  reachable or it is not.

### Worker-pool backpressure is readable from the API (B-1, 2026-07-26)
- **AN-7 stops being invisible to operators.** Every subsystem has had its own
  bounded pool since the first commit, but the only way to see one backing up
  was to scrape the metrics endpoint. `GET /api/v1/operations/bulkheads` (and
  `trstctl-cli operations bulkheads`) now reports each pool's workers,
  capacity, queue depth, computed saturation, and its
  submitted/completed/rejected/panicked counters — so "is a queue backing up,
  and which one" is one authenticated read. The snapshot is process-wide
  operational telemetry: subsystem names and numbers, never tenant or
  credential data. A control plane assembled without the bulkheaded surfaces
  answers `served: false` rather than 404, because "nothing is saturated
  because nothing is wired" is a truthful answer. Unbounded pools report 0%
  instead of dividing by zero. The new operation carries the whole contract
  chain in the same change: OpenAPI golden, the pinned SDK spec, generated FE
  types, and the feature-catalog mapping with its count ratchets raised
  deliberately.

### The Kubernetes issuer controller elects one reconciler (B1 residue, 2026-07-26)
- **N nodes stop reconciling the same cluster-scoped objects.** The agent ships
  as a DaemonSet, so every pod was reconciling the same trstctl
  `Issuer`/`ClusterIssuer`/`TrustBundle` resources — harmless, because signing
  and status writes are idempotent, but it multiplied API-server work and
  audit noise by the node count. A `coordination.k8s.io` Lease
  (`trstctl-agent-issuer-controller`, 30s, identity from the downward API's
  `POD_NAME`) now elects one reconciler with a compare-and-swap on
  `resourceVersion`, so a stale renewal loses instead of stomping the holder;
  a follower takes over within one lease duration. Missing Lease RBAC logs
  once and reconciles anyway — duplicated idempotent work beats no controller
  at all. Covered by tests for single-leader election, the cold-start create
  race, and expiry takeover.

### A maintainer transfer document (D7, 2026-07-26)
- **The operational knowledge leaves one head.** `MAINTAINERS.md` is written
  for someone who did not build this: the system's mental model in a
  paragraph, the architecture linter's eight analyzers and how to extend one
  (including why there is no `//nolint` escape hatch), the three invariants
  that have **no** analyzer and lean on dependency-closure tests instead, a
  map of where the danger is (crypto boundary, signer process, RLS store, the
  three attach seams), what each meaningful CI gate failing actually means,
  how release publishing is gated, and why the docs are grep-tested. Pairs
  with the nine existing runbooks as the transfer set.

### Dependency license audit runs in CI (D9, 2026-07-26)
- **Copyleft contamination is now caught by us, not by diligence.**
  `make license-audit` resolves every module actually linked into the shipped
  binaries (`trstctl`, `-signer`, `-agent`, `-operator`), classifies each
  license, and fails on strong copyleft (AGPL/GPL/LGPL/SSPL/CDDL/EPL) or a
  module with no recognizable license text; it runs beside govulncheck in CI
  and uploads a JSON receipt. Current state: **83 modules, zero copyleft** —
  41 Apache-2.0, 21 MIT, 19 BSD, 1 MPL-2.0, 1 public-domain. The classifier
  matches license *titles* in priority order rather than grepping for "GPL",
  because MPL-2.0's own Exhibit B names the GNU GPL as a compatible secondary
  license — a naive scan reports every MPL dependency as a GPL finding.

### Contribution terms: DCO for core, CLA only for `ee/` (D2, 2026-07-26)
- **The IP terms are written down before the first outside contribution.**
  `CONTRIBUTING.md` states the split plainly: core is MPL-2.0 and accepts
  patches under the **Developer Certificate of Origin** (`git commit -s`, no
  copyright assignment), while the proprietary `ee/` tree requires a signed
  CLA — with the honest note that most `ee/` requests can be met by a core
  change plus a seam, which stays DCO-only. A blanket CLA would tax every
  drive-by fix in core; DCO-only everywhere would leave the commercial tree
  undistributable. README links it and a PR template carries the checklist.

### Migration runs get a CLI (A0.4a, 2026-07-26)
- **`/api/v1/pqc/migrations` is no longer curl-only.** `trstctl-cli migration
  start | status | rollback` drives the licensed crypto-migration surface
  through the same route table every other command uses, with the
  `Idempotency-Key` discipline the mutating routes require. Against an
  unlicensed server the routes are absent, so the CLI reports 404 — the
  honest answer for a feature that edition does not serve. Documented in
  docs/cli.md with a worked example and mapped into the feature catalog
  (F16), so the CLI-vs-feature parity gate covers it.

### Break-glass succession is wireable; the dead migration twin is gone (A0.4b, 2026-07-26)
- **PCAS class-downgrade break-glass can now actually be configured.** The
  production minter passed a nil verifier, so a downgrade was refused
  unconditionally and `NewSignedBreakGlassAuthorizer` had only test callers.
  The signer now loads an operator-provisioned break-glass authority PUBLIC
  key from `<signer-keystore>/pcas-breakglass-authority.pem` (the same
  operator-provisions-trust pattern as the XREC plan bundle — never a
  control-plane input) and, when present, accepts a valid single-use token
  signed by that authority with durable spent-state inside the custody dir.
  Absent stays fail-closed; **present-but-unparseable fails startup** rather
  than looking configured while behaving as if it were not.
- **Deleted the dead fleet-migration twin.** `ee/pqcmigration.Orchestrator`
  (the discover→stage→reissue→track loop) and the whole `ee/fleet` package
  had zero non-test callers — both were shadowed by the differently
  architected served implementation (`ee/pqcmigration` api/server/plan) and
  by core's served CA-compromise fleet re-issuance. Removing them deletes
  ~400 lines of code that read as shipped and was not.

### Agent collector scope stated; api_key failures name their cause (A0.2c, 2026-07-26)
- **The unwired agent collectors are disclosed, not implied.** PKCS#11 token,
  Windows certificate/trust store, and in-cluster Kubernetes Secret
  collection exist as the injected-enumerator boundary in
  `internal/agent/discovery` but the shipped agent constructs no enumerator
  for them — limitations.md now says **not offered** and the package says so
  at the constructors, so nobody reads them as served. Adding one is an
  enumerator plus a flag, which is the point of the seam.
- **An `api_key` source with neither observations nor findings now says so.**
  It used to fall through to the generic "no server-side connector is
  configured for discovery source kind api_key", which read as "api_key is
  not served" when the real cause was an empty config.

### secret_store sources gain a real executor (A0.2b, 2026-07-26)
- **The creatable-but-never-runnable kind is gone.** `secret_store` sources
  now dispatch through the same served secret-manager connectors as
  `cloud_secret` (aws-secrets-manager, gcp-secret-manager, azure-key-vault,
  hashicorp-vault — the kinds share the providers config shape), instead of
  dead-ending in the generic "no server-side connector" fallback. Providers
  outside the served set (kubernetes-secrets, cicd-store) fail
  with the connector's specific "unsupported provider" refusal; building
  those listers stays demand-driven P-track work. Empty-provider errors are
  now kind-aware.

### Discovery schedules tick server-side (A0.2a, 2026-07-26)
- **"Continuous monitoring" stops needing an external cron.** A leader-only
  scheduler (`RunDiscoveryScheduler`, started with the CRL and lifecycle
  workers) sweeps every minute and queues a run for each enabled schedule
  whose source has no in-flight run and no run newer than its
  `interval_seconds` — through the exact event + projection + outbox path an
  operator-initiated run takes (AN-2/5/6), tagged
  `requested_by: discovery-scheduler`. A failed run counts as an attempt so a
  broken source retries next interval instead of hot-looping; one sweep
  queues at most 100 runs per tenant (AN-7 ahead of the bulkheaded worker).
  The due decision is a real-PostgreSQL integration test under RLS,
  including in-flight suppression, failed-run backoff, the sweep limit, and
  tenant isolation.

### Decision: the issuing CA key stays classical, on purpose (A0.3g, 2026-07-26)
- **Post-quantum keys are subject keys, not issuer keys, and that is now a
  recorded decision instead of an undisclosed ceiling.** Rationale: (1) a
  pure ML-DSA issuer breaks every stock TLS client that must chain to it,
  while an ML-DSA *subject* under a classical issuer interoperates today —
  the hybrid/pure subject leaf is where the market is; (2) the harvest-now/
  decrypt-later threat targets confidentiality (KEM), not the issuer
  signature: a classical issuing CA can be rotated to a PQ issuer when
  clients are ready, and nothing already issued becomes forgeable
  retroactively before then; (3) the mechanics (`signOpaqueTBS`'s classical
  allowlist, the hardcoded ECDSA-P256 issuing handle) are one contained
  boundary change behind `internal/crypto` when the CA-hierarchy PQC work
  (P8/F57 follow-up) schedules it — the crypto-agility property this
  architecture sells. limitations.md already discloses the ceiling; the
  roadmap owns the lift.

### The PQC census proofs run in CI on every push (A0.3f, 2026-07-26)
- **"PQC issuance is proven" stops depending on someone remembering a build
  tag.** A new required check, `pqc e2e (dodproof)`, runs
  `TestDODPQCProductionAssembly` — stock-OpenSSL pure ML-DSA-65 EST
  enrollment, the two-entry hybrid SVID Workload API response, and the
  CBOM→migration TLS rollout with rollback — against the exact shipped
  artifact on every push. The job gates loudly on an ML-DSA-capable stock
  OpenSSL (>= 3.5) so runner drift cannot silently skip the proof; the check
  is pinned into branch-protection.json, docs, and a guard test.

### The additional Workload-API SVID is audited like the classical one (A0.3e, 2026-07-26)
- **The licensed second SVID stops being invisible to the event log.** The
  Workload API's additional-issuer mint now emits the same
  `spiffe.svid.issued` audit event and credential-graph node the classical
  SVID gets, with its hint in the payload (`x509-additional:<hint>`), so
  posture can tell the pair apart. Profile parity note: the classical SVID's
  EKUs are equally fixed by the SVID signing profile, so the additional
  issuer's serverAuth/clientAuth EKUs are parity, not drift; and like every
  Workload-API SVID it is deliberately ephemeral — audited, graphed, but not
  an inventory row.

### Direct-API issuance scope decided; dead licensed twin removed (A0.3d, 2026-07-26)
- **The identity API's server-side classical keygen is a decision, not a
  gap.** `issuanceDispatcher.issueLicensed` was assigned at boot and called
  nowhere — a dormant seam diligence would flag. It is deleted; the
  dispatcher documents that ephemeral NHI identities take server-generated
  classical keys by design, and CSR-based enrollment (including licensed
  subject algorithms) belongs to the enrollment protocols through
  `protocolIssuer`, whose licensed twin is live and tested.

### ACME's algorithm transparency is pinned by test (A0.3c, 2026-07-26)
- **"ACME never parses the CSR" is now a contract, not an accident.** A new
  test drives a full RFC 8555 order with a real client and finalizes with a
  CSR whose proof-of-possession the core parser rejects; the order completes
  and the CA seam receives byte-identical CSR data. If anyone "hardens"
  finalize with a core-parser check — breaking the licensed issuer's
  ownership of subject-algorithm verification — this test fails and names
  the seam contract.

### Profiles can name post-quantum algorithms when licensed (A0.3b, 2026-07-26)
- **`allowed_key_algorithms` stops failing closed on licensed labels.**
  `crypto.Classify` gains a licensed-classifier seam
  (`InstallLicensedAlgorithmClassifier`, filled by attachPQC with
  `ee/pqc.ClassifyAlgorithm`), so profile authoring accepts ML-DSA / SLH-DSA
  / hybrid signature labels — and still rejects ML-KEM labels, which cannot
  sign certificates. Enforcement stays exact-match: a profile listing
  `ML-DSA-65` admits pure ML-DSA-65 CSRs; a hybrid enrollment carries a
  classical subject key and remains governed by its classical family label.
  Unlicensed binaries keep failing closed on all of it.

### CMP gains the licensed-CSR seam (A0.3a, 2026-07-26)
- **CMP can now carry subject algorithms the core toolchain cannot check.**
  `ParseCMPRequest` previously verified the carried PKCS#10 with the strict
  core parser *before* any licensed parser could see it, so CMP hard-rejected
  what EST already accepted. `ParseCMPRequestWithVerifier` delegates exactly
  the inner-CSR check to an injected verifier — PKIMessage protection stays
  core-verified, unconditionally — and the served mount binds the same
  licensed-aware verifier EST uses. Covered by seam tests proving the
  verifier is consulted with the exact CSR bytes, a refusing verifier fails
  closed, and tampered protection still dies even with an accepting
  verifier. (SCEP intentionally keeps the core-only path: its CMS reply
  cannot be delivered to a signature-only subject key — a protocol limit
  documented in limitations.md, not a code gap.)

### Terraform provider + Python SDK become published artifacts (B6, 2026-07-26)
- **The provider's acceptance test now actually runs.** CI drives a REAL
  `terraform apply` (pinned terraform 1.9.8, SHA256SUMS-verified download)
  through the provider's plan/apply/read/delete loop on every push —
  previously `TRSTCTL_RUN_TERRAFORM_ACC` was set nowhere and the test was
  dead weight.
- **Release tags publish the provider in the Terraform Registry layout.**
  `scripts/release/terraform-registry-assets.sh` builds per-OS/arch zips
  (binary named `terraform-provider-trstctl_v<version>`), the protocol-6.0
  registry manifest, and a GPG-signed SHA256SUMS; the release job uploads them
  as GitHub Release assets with SLSA provenance. Signing requires the
  protected `terraform-registry-signing` environment — unsigned assets are
  refused rather than emitted.
- **The Python SDK ships to PyPI and the Release.** A release job stamps the
  tag version into `clients/sdk/python`, builds sdist+wheel, `twine check`s
  them, uploads them as Release assets with SLSA provenance, and pushes to
  PyPI via the protected `pypi-publishing` environment (`PYPI_API_TOKEN`) —
  missing credentials fail loud, never skip silently.

### SPIRE upstream-authority plugin ships (B2, 2026-07-26)
- **The SPIRE plugin is now an obtainable artifact, not a build-from-source
  exercise.** `trstctl-spire-upstream-authority` joins `make build`'s `CMDS`
  and the reproducible-binary check, and every release tag publishes
  `trstctl-spire-upstream-authority-linux-{amd64,arm64}` GitHub Release assets
  with a SHA-256 manifest and their own SLSA provenance
  (`trstctl-spire-upstream-authority.intoto.jsonl`), gated on the same
  test/required-checks contexts as every other publishing job. SPIRE loads the
  plugin from its own host (`plugin_cmd`), so it deliberately stays out of the
  container image; docs/limitations.md now states the exact distribution
  contract instead of a bare "served".

### CBOM licensed posture — real FIPS targets (A0.1, 2026-07-26)
- **A licensed binary's CBOM now names its migration targets.** The MPL core
  still emits edition-neutral `licensed-*` placeholders and recognizes no
  licensed algorithm family — that fence is deliberate and unchanged. A new
  seam, `cbom.InstallLicensedPosture`, is filled from the tagged PQC attach
  block with `ee/pqc/cbomposture.CBOMTargetFor` +
  `ee/pqc/cbomposture.CBOMClassifyKey`, so with
  FeaturePQC licensed the inventory maps classical signatures →
  **ML-DSA-65 (FIPS 204)**, key establishment → **ML-KEM-768 (FIPS 203)**, and
  deprecated DSA → **SLH-DSA-SHA2-128s (FIPS 205)**; ML-DSA / ML-KEM / SLH-DSA
  / SPHINCS+ / Kyber / Dilithium / hybrid labels classify as strong and not
  quantum-vulnerable instead of "unrecognized"; and pure post-quantum assets
  carry `future-ready` — which makes `percent_migrated` a live number instead
  of a structural zero. Hybrid assets deliberately stay `migration-required`:
  they are quantum-safe today but the migration endpoint is the pure
  post-quantum algorithm. Covered by `ee/pqc/cbom_test.go`, including a mixed
  classical + post-quantum estate reporting 25% migrated.

### Static console demo enablement (demo.trstctl.com, 2026-07-25)
- **The console can now ship as a zero-backend static demo.** A build-time
  flag (`VITE_TRSTCTL_DEMO=1`, set only by the demo-site build in
  trstctl-website) makes preview mode available in a production bundle,
  lands the visitor signed-in on the showcase, and — new for preview
  everywhere — activates transport isolation: the API client refuses every
  server call before fetch, with translated error copy (2 new keys per
  catalog; digests re-pinned, machine translations flagged for review).
  The product embed never sets the flag, and a new embed-purity gate
  (`internal/webui/demo_purity_test.go`) fails the build if the committed
  console ever carries the preview identity.

### Design-review remediation (R-01…R-09, 2026-07-25)
- **Every form control in the console now actually has a style.** An external
  design review found — and we verified — that `.ui-input`, the class worn by
  ~145 inputs/selects/textareas across 11 pages, was defined in no stylesheet,
  ever: every form field rendered as raw native browser chrome (white fields
  in the flagship dark theme). The family now exists (token-correct field,
  36px to pair with buttons, themed select/textarea/file variants,
  aria-invalid state), native checkboxes/radios ride a gold `accent-color`,
  and a new foundation guard fails the build if any referenced `ui-*` class
  has no rule — it immediately caught a second stillborn class (`ui-button`,
  10 raw buttons now on the Button primitive).
- **Forms became primitives (DESIGN.md rule 14).** `Input`/`Select`/
  `Textarea` plus a `Field` unit that owns label/description/error and their
  aria wiring; piloted on Request Credential's zod+RHF form; raw-control
  counts in pages are budget-ratcheted downward (migrate-when-touched).
- **Focus is its own token (rule 2, both themes).** Focus rings rode
  `--brand-accent`, which is gold-family in light mode — collapsing the
  gold-acts/mint-focuses semantics. A dedicated `--focus` token keeps mint in
  both themes, swept through every focus ring, with a 3:1 non-text contrast
  guard and a mint-hue-family pin.
- **Discipline sweeps.** Eyebrow: nine hand-rolled tracked-uppercase clusters
  (Secrets ×8, Login) plus shell/pqc/styleguide stragglers migrated to the
  primitive, with a tracking ratchet. Shell toggles moved to the Button
  primitive, killing a focus ring class that resolved to no configured color.
  Dead tokens deleted (`--console-accent`, unused density rungs) — the suite
  was certifying them as alive. Rule 15 codifies Card-vs-`ui-panel` and
  DataGrid-vs-`ui-table` criteria; monolith pages split as touched
  (web/AGENTS.md). Repo-wide prettier normalization un-reds CI's
  format:check after the dependency refresh.

### Live dashboard tiles (S-N1, 2026-07-24)
- **Home's numbers stay current without an operator reflex.** The Dashboard's
  eight resources moved off `useResource` onto the query layer with a live-tile
  contract (certctl's PERF-H1 pattern): KPIs poll every 30s and the audit rail
  every 60s while the tab is visible, hidden tabs poll nothing, and returning
  to the tab refreshes exactly the live queries immediately. The optional-probe
  readers (NHI inventory, secrets count, open incidents, recent audit) now fail
  soft to their empty fallbacks, so a missing or erroring optional endpoint can
  never stall the first-run gate or error the whole dashboard.

### Per-locale catalog split (S-C10, 2026-07-24)
- **The entry chunk drops a third: 239 → 163 kB brotli.** The es-ES and de-DE
  production catalogs moved to per-locale modules loaded on demand by the
  I18nProvider; English (the source catalog) and the pseudo transforms stay
  eager. Until a lazy catalog resolves, lookups fall back to English — never
  to raw keys — and the tree re-renders translated the moment the module
  lands (covered by a new in-session locale-switch test). Strings are
  byte-identical to their pre-split location, so the translation-review
  digests did not move; the `satisfies` completeness contract survives in the
  split modules, and the entry size-limit budget is lowered to 185 kB to lock
  in the win.

### Compact locale wire catalogs (AUD-121, 2026-08-12)
- **Reviewed translations keep their keys; the browser stops downloading those
  keys twice.** A checked generator emits value-only lazy runtime catalogs in
  the canonical English message order, then reconstructs the keyed map when a
  locale loads. Keyed es/de sources, type-level completeness, placeholder
  checks, and review digests remain authoritative and byte-identical. The build
  rejects stale generated mirrors, and the 640 kB all-JavaScript ceiling stays
  unchanged.

### Console engineering train (S-C4 / S-C5 / S-C8 / S-C9, 2026-07-24)
- **S-C5 — the data and form layers arrive.** TanStack Query is the console's
  query layer (`src/lib/query.tsx`; provider in `AppRoutes`), piloted on
  Owners: the cache is the row truth, mutations write through and invalidate —
  the refetch `useResource` never had. Mutation forms go schema-first with
  zod + react-hook-form, piloted on Request Credential with per-field errors.
  Adoption policy in `web/AGENTS.md`: new surfaces use the new layers;
  existing pages migrate when touched.
- **S-C9 — typography primitives and a real merge fix.** `Eyebrow` and `Num`
  encode the micro-label and inline-data rules; `text-2xs` replaces the five
  `text-[10px]` arbitraries. The Eyebrow test exposed a latent bug: cn()'s
  tailwind-merge dropped the custom font-size tokens as color conflicts —
  fixed by registering the token scale, for every cn() call site.
- **S-C8 — Storybook workbench.** Storybook 10 (react-vite + a11y addon)
  renders stories against the real tokens with a dark/light toolbar; six
  starter story files cover the primitives and shared components. Coverage
  extended 2026-07-24 to the data-heavy set — DataGrid (sorting, selection +
  bulk slot, and all five list states), the full chart palette (tones,
  StatTile, Meter, BucketBar, time bars, Donut, Sparkline/AreaTrend),
  CredentialChip, the DetailDrawer/Dialog overlays, and StatePrimitives —
  10 titles / 38 stories in the static build.
- **S-C4 — Playwright e2e + visual regression, authored.** Shell smoke (rail,
  scoped sidebars, palette, the `?tab=` redirect) and masked dark-theme visual
  baselines, targeting the seeded demo stack (`npm run e2e`). Browsers were
  not installable in the authoring sandbox — first local run generates
  baselines (`--update-snapshots`).
- **Contracts.** `web/AGENTS.md` is the console's leaf contract; DESIGN.md
  rules 5/6/12 updated to the primitives and the workspaces-vs-lenses ruling;
  the root AGENTS.md now states the AN-4/6/7 enforcement asymmetry plainly;
  the visual-asset audit (design-audit/10) confirms nothing reader-facing
  depicts the retired chips shell.

### IA train closeout (S-C3 / S-C6 / S-C7, 2026-07-24)
- **S-C3 — the console code-splits by page.** Every authenticated surface is a
  lazy route chunk (70 chunks; the entry is the shell + vendor + the typed
  i18n catalogs), with a Suspense boundary at the shell outlet that announces
  loading. The compressed budget is enforced by `npm run size` (size-limit:
  entry, largest page chunk, and total shipped JS); Vite's raw-size warning
  threshold sits just above the entry so a new oversized chunk still trips it.
  Follow-up noted: per-locale catalog splitting would shrink the entry further.
- **S-C6 — the command palette groups by space and speaks verbs.** Route
  results render under space headings in rail order (Home first; spaceless
  routes last under Routes), Enter-activates-first agrees with the visible
  order, and four permission-gated verb entries land where the verb happens:
  Rotate a secret, Grant workload access, Issue SSH user certificate, and
  Preview blast radius.
- **S-C7 — the workspaces-vs-lenses rule is now written down.** A tab becomes
  a sidebar route only when it is a distinct served workspace (own evidence,
  own workflows, own name); an alternate view over the same object domain
  stays a URL-addressable in-page tab. Rulings: Secrets' six workspaces are
  routes (S-C2); Certificates' four tabs and Discovery's four tabs are lenses
  and stay. Home's five inventory counters now deep-link into their spaces,
  completing the every-number-is-a-link pass.

### Secrets workspaces as routes (S-C2, 2026-07-23)
- **The Secrets mega-page's six workspaces are sidebar routes now.** The store
  keeps `/secrets`; **Secret engines** (`/secrets/engines`), **Machine access**
  (`/secrets/access`), **One-time shares** (`/secrets/sharing`), **CI scanning**
  (`/secrets/scanning`), and **Sync targets** (`/secrets/sync`) each own a row
  in the Secrets space sidebar, grouped Store & engines / Access & sharing /
  Delivery & scanning. The in-page tab strip is gone; historical
  `/secrets?tab=` deep links redirect permanently with their remaining query
  intact (the C-A1 `/platform` precedent). Every route carries its own H1 and
  title (naming parity), RBAC gate, and feature evidence; the rail-row budget
  consciously grows by five (ceiling 38).

### Unified shell (spaces IA, 2026-07-23)
- **The console is now five spaces behind an icon rail.** The S-B2
  chips-in-sidebar module switcher became a left rail of spaces that each own
  every surface of one concern — *Certificates & PKI*, *Secrets*,
  *Workload & SSH*, *Posture & response*, and *Platform* — with Home carrying
  the Dashboard, Journeys, and the needs-action worklists. The URL decides the
  active space (deep links light up their owning space; picking a space lands
  on its first permitted route), the per-space audit lenses and 34-row rail
  budget survive, and no route URL, nav label, or feature ID changed, so
  bookmarks and API couplings are untouched. Operator docs (web-console, the
  demo click-through, platform-and-api) describe the new shell.
- **DA-02 closed — the secrets auth-method console.** Secrets → Access now grants
  workload credentials in-console (scoped standing tokens or TTL-bound ephemeral
  keys, reveal-once, list + revoke), projects the configured machine-auth methods
  (issuer, audience rules, scopes, source) with a per-tenant, event-sourced
  disable/enable overlay enforced at the login exchange, and serves the
  issued-session ledger (`GET /api/v1/secrets/sessions`) with idempotent,
  event-sourced revocation (`machine_sessions` projection, migration 0086).
  New API surface: `GET /api/v1/secrets/auth-methods`,
  `POST /api/v1/secrets/sessions/{id}/revoke`,
  `POST /api/v1/secrets/auth-methods/{name}/disable|enable` — with CLI parity
  (`secrets auth-methods list|disable|enable`, `secrets sessions list|revoke`).
- **The `/platform` grab-bag became three routes** — `/admin/access`,
  `/admin/system`, `/admin/editions` — each deep-linkable and fetch-scoped.
  This is the train's only URL change and every historical `/platform` (and
  tab) link redirects permanently; rollback is a nav-config revert.
- **DA-10:** incident intake uses identity pickers and served vocabularies —
  no more pasting raw UUIDs on faith. **DA-14 closed as a class:** the i18n
  extraction ratchet (now AST-based) reads zero hardcoded user-facing strings
  and is sealed at zero. **47-day readiness** panel now lives on the global
  home, ahead of the 2027-03-15 100-day step.
- **Locales:** Spanish is joined by **German (de-DE)** as a production locale;
  both catalogs are completeness-enforced by the type system. Long-tail
  machine-seeded entries are enumerated for human translation passes.
- Rail budget consciously re-set 32 → 34 rows for the admin split; entity-noun
  consolidation deliberately deferred behind an evidence checklist.

### Security & hardening
- Remediation pass (R0–R9) hardening the served, multi-tenant profile: served
  end-to-end **revocation** (a revoked credential stops validating in the product's
  inventory/records), an idempotent first-API-token bootstrap, served X.509 issuance
  with CDP/AIA/SKI and certificate-profile enforcement, quorum-gated cross-signing,
  versioned event envelopes with version-aware projections, bounded/tenant-scoped
  lifecycle history, and TTL'd idempotency keys.
- Supply chain: GitHub Actions and base/runtime images pinned by digest, the
  embedded-PostgreSQL binary pinned against a committed provenance manifest, a
  CycloneDX SBOM and `govulncheck` gate in CI, CODEOWNERS over the root-of-trust
  paths with required code-owner review, and checksum-verified CI tool installs.
- Docs/observability honesty: a reality-tested `docs/limitations.md` that states
  served-vs-library status for every advertised capability, so the binary cannot
  silently over-claim.

### Added
- `CHANGELOG.md` (this file), linked from the README and SECURITY.md (DOCS-005).

### Changed — web console information architecture (IA train)

*Superseded within this release: the module-switcher chrome below evolved into
the five-space unified shell (see "Unified shell (spaces IA)" above). The
defect-class guards it introduced — `naming_parity`, `nav_completeness`,
`module_map`, demo-data isolation, docs IA parity — carry forward unchanged
and still gate the spaces IA.*

- **Option A — refined rail.** The sidebar is re-grouped into four question-shaped
  bands (Inventory / Issue & automate / Detect & respond / Govern & administer) and
  every previously hidden product surface (CA hierarchy, certificate profiles, SSH
  trust, code signing, operations, notifications, privacy, integrate, API explorer)
  is now visible in navigation. One name per surface: nav label, page `<h1>`, and
  document title agree everywhere (a permanent `naming_parity` guard enforces it).
  Platform gains a dedicated **Editions & license** tab, quarantining commercial
  licensing rows off the operational Access and System tabs.
- **Option B — module workspaces.** A top-of-rail **Module** switcher (Certificates &
  PKI, Secrets, SSH, Signing, Fleet) scopes the middle band to one product; the
  cross-domain global planes (identities, discovery, risk, posture, graph, incidents,
  approvals, governance, audit) stay visible under every module. Module homes carry a
  thin served KPI strip that deep-links into filtered lists. The shared audit stream
  gains per-module lenses via `?module=` with a clearable scope chip — one stream, one
  hash chain, N lenses, never per-module silos.
- **Dashboard integrity & renew.** Real-mode dashboards render served data only (the
  fabricated demo trend/activity/bands are gone) and the four action KPIs are wired to
  live counts; the expiring-certificate worklist and detail drawer now offer Renew,
  wired to the identity lifecycle transition.
- **No route/URL changes.** The entire IA change is navigation chrome; every route
  keeps its path, so deep links, journeys, and muscle memory survive. Permanent CI
  guards (`naming_parity`, `nav_completeness`, `module_map`, demo-data isolation, docs
  IA parity) keep the fixed defect classes from returning.

## [0.5.4] - 2026-06-27

### Added
- Expanded the shipped console from a basic shell into task-oriented workspaces for
  certificate lifecycle, secrets, discovery, NHI risk and posture, CA hierarchy,
  incidents, governance, privacy, integrations, and platform operations. The same
  train added feature-to-route coverage guards, generated API types, responsive
  navigation, localization, accessibility checks, and a read-only preview identity.
- Served the next platform integrations: secret rotation/sync and scanning,
  SSO/SCIM/ABAC and break-glass administration, a cert-manager issuer controller,
  Terraform and Python clients, signed compliance evidence, OTLP export, passive
  federation, JIT access, signed WASM plugins, and cloud managed-key custody.
- Introduced the single-repository open-core edition boundary: core/Enterprise/
  Provider status, offline license seams, Provider metering/branding/isolation, and
  explicit Enterprise fences for remediation, federation, managed-key/KMIP custody,
  and governance evidence.

### Changed
- Reworked the console around shared data grids, task-first navigation, responsive
  mobile/desktop layouts, theme controls, and served-state disclosures instead of
  advertising routes without product wiring.

### Security
- Required independent signer authorization, replay-safe issuance recovery,
  encrypted disaster-recovery backups, bounded public protocol/request state,
  bounded outbox execution, default-private optional AI egress, digest-pinned
  deployment artifacts, and release-gate checks before publishing.

## [0.5.3] - 2026-06-18

### Fixed
- Stopped the release workflow from uploading unsigned Windows agent artifacts.
- Corrected the release workflow's shellcheck failure.
- Prepared the compose-profile artifacts consumed by the repository lint gates.

## [0.5.2] - 2026-06-18

### Security
- Hardened tenant offboarding, tenant-bound machine login, byte-backed secret and
  provider credentials, signer content authorization, ceremony purpose binding,
  certificate-profile EKU enforcement, SSRF-protected notifications, bounded
  request parsers, and the local-development plaintext transport exception.
- Made the architecture analyzer run as a repository-wide vet tool and added
  regression guards for tenancy, crypto custody, signer isolation, idempotency,
  outbox/bulkhead behavior, release provenance, and served-surface wiring.

### Fixed
- Routed lifecycle renewal and ACME revocation through persisted platform state,
  rebuilt agent/profile projections from events, made CRL reads side-effect free,
  versioned legacy secret events, and made rotation/reconciliation replay-safe.
- Productized disaster recovery with streamed restore, under-replicated JetStream
  fail-closed behavior, fair outbox leasing, online lease indexes, migration-lock
  polling, isolated-signer Helm wiring, and pinned agent enrollment transport.
- Added stock-client conformance for ACME, EST, SCEP, CMP, and RFC 3161, then fixed
  their CI/release fixtures, OPA v1 policy compatibility, and SCEP AES envelopes.

## [0.5.1] - 2026-06-16

### Added
- Added and exercised SCEP, CMP, MDM enrollment, the constrained-device EST client,
  SPIFFE workload identity and attesters, incident response, SSH CA workflows, code
  signing, PQC migration, the secrets/dynamic-secret/KMIP stack, discovery and
  governance, and the grounded read-only AI/MCP surface.
- Wired the assembled binary to serve issuance protocols, OIDC sessions, the React
  console, signed WASM plugins, the steady-state agent channel, the Kubernetes
  operator, cross-node signer mTLS, FIPS builds, and BYOK/HSM key lifecycle.

### Security
- Completed the first broad hardening sweep across revocation, signer
  abuse-resistance and dual control, tenant isolation, parser bounds and fuzzing,
  event-spine resilience, deployment defaults, release signing/provenance, and
  architecture guard tests.

## [0.5.0] - 2026-06-13
- Hardening milestone toward an enterprise-GA bar for the self-hosted, multi-tenant
  profile: isolated signer custody (sealed CA key persisted across restarts), the
  assembled control-plane server (`cmd/trstctl` → `internal/server`) serving the
  event spine, projections, orchestrator, and REST API, and the architecture linter
  (`tools/trstctllint`) enforcing AN-1/AN-3/AN-5/AN-8 in CI.

## [0.4] - 2026-05-31
- Pre-release development milestone.

## [0.3] - 2026-05-31
- Pre-release development milestone.

## [0.2] - 2026-05-31
- Pre-release development milestone.

## [0.1] - 2026-05-31
- Initial tagged development milestone.

[Unreleased]: https://github.com/ctlplne/trstctl/compare/v0.5.4...HEAD
[0.6.3]: https://github.com/ctlplne/trstctl/releases/tag/v0.6.3
[0.7.0]: https://github.com/ctlplne/trstctl/releases/tag/v0.7.0
[0.6.0]: https://github.com/ctlplne/trstctl/releases/tag/v0.6.0
[0.5.4]: https://github.com/ctlplne/trstctl/releases/tag/v0.5.4
[0.5.3]: https://github.com/ctlplne/trstctl/releases/tag/v0.5.3
[0.5.2]: https://github.com/ctlplne/trstctl/releases/tag/v0.5.2
[0.5.1]: https://github.com/ctlplne/trstctl/releases/tag/v0.5.1
[0.5.0]: https://github.com/ctlplne/trstctl/releases/tag/v0.5.0
[0.4]: https://github.com/ctlplne/trstctl/releases/tag/v0.4
[0.3]: https://github.com/ctlplne/trstctl/releases/tag/v0.3
[0.2]: https://github.com/ctlplne/trstctl/releases/tag/v0.2
[0.1]: https://github.com/ctlplne/trstctl/releases/tag/v0.1
