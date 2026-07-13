export const defaultLocale = "en-US";
export const defaultTimeZone = "UTC";
export const supportedLocales = ["en-US", "es-ES", "en-XA", "ar-XB"] as const;
export const productionLocales = ["en-US", "es-ES"] as const;
export const pseudoLocales = ["en-XA", "ar-XB"] as const;

export type Locale = (typeof supportedLocales)[number];
export type MessageValues = Record<string, number | string>;

export const messages = {
  "app.loading": {
    defaultMessage: "Loading...",
    description: "Status text shown while the authenticated session is loading.",
  },
  "app.brand.name": {
    defaultMessage: "trstctl",
    description: "Product wordmark in the global shell.",
  },
  "app.brand.subtitle": {
    defaultMessage: "control plane",
    description: "Short product descriptor under the wordmark.",
  },
  "app.skipToMain": {
    defaultMessage: "Skip to main content",
    description: "Keyboard skip-link label.",
  },
  "credentialChip.copy": {
    defaultMessage: "Copy {label}",
    description: "Accessible label for the copy button on a credential chip; label names the identifier kind (e.g. serial number).",
  },
  "credentialChip.copied": {
    defaultMessage: "Copied to clipboard",
    description: "Screen-reader announcement after a credential chip value is copied.",
  },
  "graph.view.zoomIn": {
    defaultMessage: "Zoom in",
    description: "Accessible label for the graph map zoom-in control.",
  },
  "graph.view.zoomOut": {
    defaultMessage: "Zoom out",
    description: "Accessible label for the graph map zoom-out control.",
  },
  "graph.view.resetView": {
    defaultMessage: "Reset view",
    description: "Accessible label for the graph map control that resets zoom and pan.",
  },
  "graph.explorer.delegatedHint": {
    defaultMessage: "Results are painted on the map below and detailed in the analysis rail.",
    description: "Hint under the blast-radius explorer on the Graph page explaining where shared analysis results appear.",
  },
  "certificates.tabs.inventory": {
    defaultMessage: "Inventory",
    description: "Certificates page tab: the primary certificate table.",
  },
  "certificates.tabs.health": {
    defaultMessage: "Estate health",
    description: "Certificates page tab: health, rogue findings, and KPI panels.",
  },
  "certificates.tabs.crlct": {
    defaultMessage: "CRL & CT",
    description: "Certificates page tab: CRL distribution and Certificate Transparency submission.",
  },
  "certificates.tabs.renewal": {
    defaultMessage: "Renewal readiness",
    description: "Certificates page tab: renewal readiness panels and deployment receipts.",
  },
  "pqc.readiness.aria": {
    defaultMessage: "PQC migration readiness",
    description: "Accessible label for the post-quantum migration progress meter.",
  },
  "pqc.readiness.migrated": {
    defaultMessage: "{percent}% migrated",
    description: "Post-quantum migration percentage shown under the progress meter.",
  },
  "pqc.readiness.totalAssets": {
    defaultMessage: "Total assets",
    description: "Metric label for total CBOM assets in the post-quantum readiness summary.",
  },
  "pqc.readiness.quantumVulnerable": {
    defaultMessage: "Quantum-vulnerable assets",
    description: "Metric label for CBOM assets that still need post-quantum migration.",
  },
  "pqc.readiness.readyAssets": {
    defaultMessage: "PQC-ready assets",
    description: "Metric label for CBOM assets already post-quantum ready.",
  },
  "certificates.ct.launch": {
    defaultMessage: "Submit to CT",
    description: "Button that opens the Certificate Transparency submission dialog.",
  },
  "certificates.ct.launchDescription": {
    defaultMessage: "Queue signed certificates for Certificate Transparency log submission.",
    description: "Description next to the Submit to CT button.",
  },
  "secrets.tabs.store": {
    defaultMessage: "Store",
    description: "Secrets page tab: browse, import, and manage the native secret store.",
  },
  "secrets.tabs.access": {
    defaultMessage: "Access",
    description: "Secrets page tab: developer access snippets and machine login.",
  },
  "secrets.tabs.sharing": {
    defaultMessage: "Sharing",
    description: "Secrets page tab: one-time shares and ephemeral API keys.",
  },
  "secrets.tabs.engines": {
    defaultMessage: "Engines",
    description: "Secrets page tab: PKI, dynamic secrets, and transit/KMIP engines.",
  },
  "secrets.tabs.scanning": {
    defaultMessage: "CI scanning",
    description: "Secrets page tab: code and CI secret scanning bridge.",
  },
  "secrets.tabs.sync": {
    defaultMessage: "Sync",
    description: "Secrets page tab: secret sync and platform integrations.",
  },
  "discovery.tabs.findings": {
    defaultMessage: "Findings",
    description: "Discovery page tab: findings table plus CT/drift/monitoring posture.",
  },
  "discovery.tabs.sources": {
    defaultMessage: "Sources",
    description: "Discovery page tab: source table and create-source form.",
  },
  "discovery.tabs.schedules": {
    defaultMessage: "Schedules",
    description: "Discovery page tab: schedule table and create-schedule form.",
  },
  "discovery.tabs.runs": {
    defaultMessage: "Runs",
    description: "Discovery page tab: discovery run history.",
  },
  "platform.tabs.access": {
    defaultMessage: "Access administration",
    description: "Platform page tab: membership, tokens, and offboarding — the operational surface.",
  },
  "platform.tabs.posture": {
    defaultMessage: "System posture",
    description: "Platform page tab: read-only packaging, regional, scale, and support disclosures.",
  },
  "identities.decommission.heading": {
    defaultMessage: "Decommission by signal",
    description: "Heading for the identity decommission workflow section.",
  },
  "request.wizard.profile.label": {
    defaultMessage: "Choose profile",
    description: "Request-credential wizard step 1 title.",
  },
  "request.wizard.profile.description": {
    defaultMessage: "The issuance profile governs key type, lifetime, and how many approvals the request needs.",
    description: "Request-credential wizard step 1 description.",
  },
  "request.wizard.details.label": {
    defaultMessage: "Name the credential",
    description: "Request-credential wizard step 2 title.",
  },
  "request.wizard.details.description": {
    defaultMessage: "Approvers see exactly this: what the credential is called, who owns it, and why it exists.",
    description: "Request-credential wizard step 2 description.",
  },
  "request.wizard.review.label": {
    defaultMessage: "Review and submit",
    description: "Request-credential wizard step 3 title.",
  },
  "request.wizard.review.description": {
    defaultMessage: "Requesting and approving stay separate steps — nothing is minted until an approver signs off.",
    description: "Request-credential wizard step 3 description.",
  },
  "request.wizard.nextDetails": {
    defaultMessage: "Next: name it",
    description: "Request-credential wizard button from step 1 to step 2.",
  },
  "wizard.protocols.stepLabel": {
    defaultMessage: "Enable protocols",
    description: "First-run wizard protocol activation step label.",
  },
  "wizard.protocols.stepDescription": {
    defaultMessage: "Activate the tenant-bound evaluation profile so standard enrollment clients can reach every shipped protocol.",
    description: "First-run wizard protocol activation step description.",
  },
  "wizard.protocols.heading": {
    defaultMessage: "Enable enrollment protocols",
    description: "Heading for the first-run protocol activation step.",
  },
  "wizard.protocols.description": {
    defaultMessage:
      "The evaluation profile assembles ACME, EST, SCEP, CMP, SSH, TSA, and SPIFFE for this tenant. Activating it records durable server state before any responder opens; this is not a browser-only toggle.",
    description: "Explains the durable server-side effect of enabling the eval protocol profile.",
  },
  "wizard.protocols.loading": {
    defaultMessage: "Reading protocol status...",
    description: "Status shown while the first-run wizard reads protocol profile state.",
  },
  "wizard.protocols.responders": {
    defaultMessage: "Shipped responders: {protocols}.",
    description: "List of protocol responders assembled by the eval profile.",
  },
  "wizard.protocols.active": {
    defaultMessage: "Eval protocol profile is active for this tenant.",
    description: "Confirmation after the eval profile activation event is recorded.",
  },
  "wizard.protocols.activate": {
    defaultMessage: "Activate eval protocol profile",
    description: "Button that durably activates the eval enrollment profile.",
  },
  "wizard.protocols.unavailable": {
    defaultMessage:
      "This deployment did not select the eval profile. Protocol exposure remains under the operator's explicit production configuration, so setup can continue without changing it.",
    description: "First-run explanation when production uses explicit per-protocol configuration.",
  },
  "wizard.protocols.retry": {
    defaultMessage: "Retry protocol status",
    description: "Button that retries reading the served protocol profile state.",
  },
  "wizard.protocols.statusError": {
    defaultMessage: "Could not read protocol setup status: {error}",
    description: "Error shown when the first-run wizard cannot read protocol profile state.",
  },
  "wizard.protocols.activationError": {
    defaultMessage: "Could not activate the eval protocol profile: {error}",
    description: "Error shown when durable protocol profile activation fails.",
  },
  "wizard.protocols.inactiveError": {
    defaultMessage: "server returned an inactive profile",
    description: "Diagnostic when an activation response does not report active state.",
  },
  "wizard.protocols.summaryActive": {
    defaultMessage: "Eval profile active",
    description: "Protocol-profile value in the first-run completion summary.",
  },
  "wizard.protocols.summaryOperator": {
    defaultMessage: "Operator-configured profile",
    description: "Completion-summary value when production uses explicit protocol configuration.",
  },
  "wizard.protocols.next": {
    defaultMessage: "Next: enable protocols",
    description: "First-run wizard button from issuer confirmation to protocol activation.",
  },
  "wizard.header.description": {
    defaultMessage: "Connect an issuer, enable enrollment protocols, issue a certificate, verify configured integrations, enroll an agent, and finish.",
    description: "Description at the top of the first-run wizard.",
  },
  "wizard.integrations.stepLabel": {
    defaultMessage: "Prove integrations",
    description: "First-run carousel label for optional configured integration verification.",
  },
  "wizard.integrations.stepDescription": {
    defaultMessage: "Exercise connector, upstream-CA, and dynamic-secret operations against systems you configured.",
    description: "First-run carousel description for optional integration verification.",
  },
  "wizard.integrations.heading": {
    defaultMessage: "Verify configured integrations",
    description: "Heading for the optional first-run integration verification step.",
  },
  "wizard.integrations.description": {
    defaultMessage:
      "These checks use the same product routes as day-two automation. They require systems configured by an operator; you can skip this optional proof on a core-only install.",
    description: "Explains the requirements and optional nature of first-run integration verification.",
  },
  "wizard.integrations.loading": {
    defaultMessage: "Loading integration catalogs...",
    description: "Status while the wizard reads connector and upstream-CA catalogs.",
  },
  "wizard.integrations.connector.heading": {
    defaultMessage: "Deploy the issued identity through a connector",
    description: "Heading for the first-run connector deployment proof.",
  },
  "wizard.integrations.connector.targetName": {
    defaultMessage: "Target name",
    description: "Label for the connector target name in the first-run wizard.",
  },
  "wizard.integrations.connector.config": {
    defaultMessage: "Connector target config",
    description: "Label for JSON connector configuration in the first-run wizard.",
  },
  "wizard.integrations.externalCA.heading": {
    defaultMessage: "Issue with a configured upstream CA",
    description: "Heading for first-run upstream-CA issuance verification.",
  },
  "wizard.integrations.externalCA.label": {
    defaultMessage: "External CA",
    description: "Label for the upstream-CA selector in the first-run wizard.",
  },
  "wizard.integrations.externalCA.none": {
    defaultMessage: "No configured upstream CA",
    description: "Option shown when no upstream CA is configured.",
  },
  "wizard.integrations.externalCA.csr": {
    defaultMessage: "External CA CSR",
    description: "Label for the PEM CSR submitted to an upstream CA.",
  },
  "wizard.integrations.externalCA.dns": {
    defaultMessage: "External CA DNS names",
    description: "Label for comma-separated DNS names requested from an upstream CA.",
  },
  "wizard.integrations.externalCA.dnsPlaceholder": {
    defaultMessage: "payments.example.com, api.example.com",
    description: "Example upstream-CA DNS names.",
  },
  "wizard.integrations.lease.heading": {
    defaultMessage: "Issue a short-lived dynamic secret",
    description: "Heading for first-run dynamic-secret lease verification.",
  },
  "wizard.integrations.lease.provider": {
    defaultMessage: "Lease provider",
    description: "Label for a configured dynamic-secret provider.",
  },
  "wizard.integrations.lease.role": {
    defaultMessage: "Lease role",
    description: "Label for a provider-specific dynamic-secret role.",
  },
  "wizard.integrations.skip": {
    defaultMessage: "Skip integration proof for now",
    description: "Button that lets a core-only install defer configured integration verification.",
  },
  "codesign.digest.placeholder": {
    defaultMessage: "sha256:<64 hexadecimal characters>",
    description: "Placeholder showing the required code-signing artifact digest format.",
  },
  "codesign.receipt.fulcioSAN": {
    defaultMessage: "Verified Fulcio SAN",
    description: "Code-signing receipt label for the verified Fulcio identity SAN.",
  },
  "codesign.receipt.transparencyDestination": {
    defaultMessage: "Transparency destination",
    description: "Code-signing receipt label for the transparency log destination.",
  },
  "codesign.receipt.signatureBase64": {
    defaultMessage: "Signature (base64)",
    description: "Code-signing receipt label for the base64 signature.",
  },
  "codesign.receipt.downloadSignature": {
    defaultMessage: "Download signature",
    description: "Link that downloads the returned artifact signature.",
  },
  "operations.status.queued": {
    defaultMessage: "Queued",
    description: "Operations-page status filter for queued work.",
  },
  "certificates.ingest.pem.label": {
    defaultMessage: "Paste the certificate",
    description: "Add-certificate wizard step 1 title.",
  },
  "certificates.ingest.pem.description": {
    defaultMessage: "Public certificate PEM only — private keys never belong in this form.",
    description: "Add-certificate wizard step 1 description.",
  },
  "certificates.ingest.placement.label": {
    defaultMessage: "Assign ownership",
    description: "Add-certificate wizard step 2 title.",
  },
  "certificates.ingest.placement.description": {
    defaultMessage: "Pick the accountable owner and record where the certificate is deployed.",
    description: "Add-certificate wizard step 2 description.",
  },
  "certificates.ingest.review.label": {
    defaultMessage: "Review and ingest",
    description: "Add-certificate wizard step 3 title.",
  },
  "certificates.ingest.review.description": {
    defaultMessage: "The certificate joins the inventory immediately and shows up in estate health.",
    description: "Add-certificate wizard step 3 description.",
  },
  "certificates.ingest.nextPlacement": {
    defaultMessage: "Next: assign ownership",
    description: "Add-certificate wizard button from step 1 to step 2.",
  },
  "certificates.ingest.nextReview": {
    defaultMessage: "Next: review",
    description: "Add-certificate wizard button from step 2 to step 3.",
  },
  "certificates.ingest.ownerUnassigned": {
    defaultMessage: "No owner (assign later)",
    description: "Owner picker option for ingesting a certificate without an owner.",
  },
  "nav.item.journeys": {
    defaultMessage: "Journeys",
    description: "Sidebar label for the guided-journeys hub.",
  },
  "journeys.eyebrow": {
    defaultMessage: "Guided paths",
    description: "Eyebrow above the Journeys page title.",
  },
  "journeys.description": {
    defaultMessage:
      "The documented operator journeys as live checklists: every step is one click to the right place, and finished steps check themselves off from live tenant data.",
    description: "Journeys page description.",
  },
  "journeys.listLabel": {
    defaultMessage: "Available journeys",
    description: "Accessible label for the journey picker list.",
  },
  "journeys.progress": {
    defaultMessage: "{done} of {total} steps done",
    description: "Progress line on a journey card.",
  },
  "journeys.census.verified": {
    defaultMessage: "Verified path · shipped wiring {passed}/{total}",
    description: "Generated shipped-binary census badge on every journey card.",
  },
  "journeys.open": {
    defaultMessage: "Take me there",
    description: "Primary button on a journey step that deep-links to the right page.",
  },
  "journeys.refresh": {
    defaultMessage: "Refresh status",
    description: "Button that re-checks journey step completion from served data.",
  },
  "journeys.doc": {
    defaultMessage: "Reference walkthrough",
    description: "Label before the path of the long-form journey doc.",
  },
  "journeys.status.done": {
    defaultMessage: "Done",
    description: "Badge for a completed journey step.",
  },
  "journeys.status.pending": {
    defaultMessage: "Pending",
    description: "Badge for an incomplete journey step.",
  },
  "journeys.fc.title": {
    defaultMessage: "First certificate",
    description: "Journey title: first certificate.",
  },
  "journeys.fc.description": {
    defaultMessage: "From an empty control plane to a minted, inventoried certificate.",
    description: "Journey description: first certificate.",
  },
  "journeys.fc.wizard.title": {
    defaultMessage: "Connect an issuer and enroll an agent",
    description: "First-certificate journey step 1 title.",
  },
  "journeys.fc.wizard.body": {
    defaultMessage: "The setup wizard provisions the signer-backed internal CA and brings your first agent online.",
    description: "First-certificate journey step 1 body.",
  },
  "journeys.fc.request.title": {
    defaultMessage: "Request the credential",
    description: "First-certificate journey step 2 title.",
  },
  "journeys.fc.request.body": {
    defaultMessage: "Pick a profile and name the credential — approval stays a separate step, so nobody self-issues.",
    description: "First-certificate journey step 2 body.",
  },
  "journeys.fc.approve.title": {
    defaultMessage: "Approve it",
    description: "First-certificate journey step 3 title.",
  },
  "journeys.fc.approve.body": {
    defaultMessage: "A second operator signs off in the approvals queue; issuance happens only after the gate.",
    description: "First-certificate journey step 3 body.",
  },
  "journeys.fc.inventory.title": {
    defaultMessage: "See it in inventory",
    description: "First-certificate journey step 4 title.",
  },
  "journeys.fc.inventory.body": {
    defaultMessage: "The issued certificate lands in the inventory and starts counting toward estate health.",
    description: "First-certificate journey step 4 body.",
  },
  "journeys.mig.title": {
    defaultMessage: "Migrate from an existing CA",
    description: "Journey title: CA migration.",
  },
  "journeys.mig.description": {
    defaultMessage: "Find everything the old CA issued, pin your rules, and cut new issuance over deliberately.",
    description: "Journey description: CA migration.",
  },
  "journeys.mig.source.title": {
    defaultMessage: "Point discovery at your estate",
    description: "CA-migration journey step 1 title.",
  },
  "journeys.mig.source.body": {
    defaultMessage: "Create a network source covering the hosts and ranges your old CA issued for.",
    description: "CA-migration journey step 1 body.",
  },
  "journeys.mig.scan.title": {
    defaultMessage: "Queue the first scan",
    description: "CA-migration journey step 2 title.",
  },
  "journeys.mig.scan.body": {
    defaultMessage: "Run the source — findings stream into the console as the scan walks your targets.",
    description: "CA-migration journey step 2 body.",
  },
  "journeys.mig.findings.title": {
    defaultMessage: "Review what was found",
    description: "CA-migration journey step 3 title.",
  },
  "journeys.mig.findings.body": {
    defaultMessage: "Triage discovered certificates straight from the findings table: claim, tag, or dismiss.",
    description: "CA-migration journey step 3 body.",
  },
  "journeys.mig.profile.title": {
    defaultMessage: "Pin your issuance rules",
    description: "CA-migration journey step 4 title.",
  },
  "journeys.mig.profile.body": {
    defaultMessage: "A profile locks algorithms, lifetimes, and usages before any new issuance cuts over.",
    description: "CA-migration journey step 4 body.",
  },
  "journeys.mig.request.title": {
    defaultMessage: "Cut new issuance to trstctl",
    description: "CA-migration journey step 5 title.",
  },
  "journeys.mig.request.body": {
    defaultMessage: "Request replacements against the profile; the approval gate keeps the cutover deliberate.",
    description: "CA-migration journey step 5 body.",
  },
  "journeys.mig.health.title": {
    defaultMessage: "Watch estate health",
    description: "CA-migration journey step 6 title.",
  },
  "journeys.mig.health.body": {
    defaultMessage: "Estate health tracks external versus issued sources as the migration drains the old CA.",
    description: "CA-migration journey step 6 body.",
  },
  "journeys.ir.title": {
    defaultMessage: "Respond to a compromise",
    description: "Journey title: incident response.",
  },
  "journeys.ir.description": {
    defaultMessage: "Scope the blast radius, replace before you revoke, and leave a sealed evidence trail.",
    description: "Journey description: incident response.",
  },
  "journeys.ir.blast.title": {
    defaultMessage: "Scope the blast radius",
    description: "Incident journey step 1 title.",
  },
  "journeys.ir.blast.body": {
    defaultMessage: "Select the compromised credential on the graph and analyze — the impact is painted on the map.",
    description: "Incident journey step 1 body.",
  },
  "journeys.ir.contain.title": {
    defaultMessage: "Replace, then revoke",
    description: "Incident journey step 2 title.",
  },
  "journeys.ir.contain.body": {
    defaultMessage: "The incident workflow provisions the replacement before the compromised credential is revoked.",
    description: "Incident journey step 2 body.",
  },
  "journeys.ir.verify.title": {
    defaultMessage: "Verify revocation",
    description: "Incident journey step 3 title.",
  },
  "journeys.ir.verify.body": {
    defaultMessage: "Confirm the credential shows revoked in inventory and CRL distribution has picked it up.",
    description: "Incident journey step 3 body.",
  },
  "journeys.ir.evidence.title": {
    defaultMessage: "Collect the evidence",
    description: "Incident journey step 4 title.",
  },
  "journeys.ir.evidence.body": {
    defaultMessage: "The audit trail and its signed export are the incident's evidence pack.",
    description: "Incident journey step 4 body.",
  },
  "journeys.copy": {
    defaultMessage: "Copy command",
    description: "Button that copies a journey step's command to the clipboard.",
  },
  "journeys.copied": {
    defaultMessage: "Copied",
    description: "Copy-command button state after copying.",
  },
  "journeys.markDone": {
    defaultMessage: "Mark step done",
    description: "Toggle that manually completes a journey step the console cannot detect.",
  },
  "journeys.undoDone": {
    defaultMessage: "Mark as not done",
    description: "Toggle that clears a manual journey-step completion mark.",
  },
  "journeys.fleet.title": { defaultMessage: "Automate fleet TLS", description: "Journey title: ACME fleet automation." },
  "journeys.fleet.description": {
    defaultMessage: "Machines enroll and renew themselves over ACME with DNS-01 proof — no humans holding certificates.",
    description: "Journey description: ACME fleet automation.",
  },
  "journeys.fleet.protocols.title": { defaultMessage: "Inspect the ACME surface", description: "Fleet journey step title." },
  "journeys.fleet.protocols.body": {
    defaultMessage: "The Protocols page shows the ACME directory, tenant binding, profile gates, and live responder status.",
    description: "Fleet journey step body.",
  },
  "journeys.fleet.dns.title": { defaultMessage: "Delegate DNS-01 validation", description: "Fleet journey step title." },
  "journeys.fleet.dns.body": {
    defaultMessage: "Point _acme-challenge at the validation zone by CNAME; DNS-01 provider configs and the preflight check live here.",
    description: "Fleet journey step body.",
  },
  "journeys.fleet.certbot.title": { defaultMessage: "Point an ACME client at the directory", description: "Fleet journey step title." },
  "journeys.fleet.certbot.body": {
    defaultMessage: "Any ACME client works; certbot with DNS-01 covers wildcards and hosts with unreachable ports.",
    description: "Fleet journey step body.",
  },
  "journeys.fleet.bindings.title": { defaultMessage: "Bind certificates to their endpoints", description: "Fleet journey step title." },
  "journeys.fleet.bindings.body": {
    defaultMessage: "One endpoint-binding call queues issue and deploy together; delivery receipts land under Renewal readiness.",
    description: "Fleet journey step body.",
  },
  "journeys.k8s.title": { defaultMessage: "Kubernetes workload identity", description: "Journey title: Kubernetes workload identity." },
  "journeys.k8s.description": {
    defaultMessage: "Short-lived certificates for workloads with attestation before trust — no static secrets in pods.",
    description: "Journey description: Kubernetes workload identity.",
  },
  "journeys.k8s.trust.title": { defaultMessage: "Register the cluster's attester", description: "K8s journey step title." },
  "journeys.k8s.trust.body": {
    defaultMessage: "Add the cluster JWKS as an attester trust source on the Workloads page — attestation before trust.",
    description: "K8s journey step body.",
  },
  "journeys.k8s.spiffe.title": { defaultMessage: "Enable the SPIFFE Workload API", description: "K8s journey step title." },
  "journeys.k8s.spiffe.body": {
    defaultMessage: "Protocols shows the trust-domain and socket requirements plus live responder status for SVID issuance.",
    description: "K8s journey step body.",
  },
  "journeys.k8s.register.title": { defaultMessage: "Register workloads as identities", description: "K8s journey step title." },
  "journeys.k8s.register.body": {
    defaultMessage: "Each service account becomes a managed identity so its certificates are inventoried and owned.",
    description: "K8s journey step body.",
  },
  "journeys.k8s.integrate.title": { defaultMessage: "Pick your integration path", description: "K8s journey step title." },
  "journeys.k8s.integrate.body": {
    defaultMessage: "cert-manager ClusterIssuer, native CertificateSigningRequests, or SPIRE upstream — the reference doc has the manifests.",
    description: "K8s journey step body.",
  },
  "journeys.k8s.verify.title": { defaultMessage: "Verify SVIDs are rotating", description: "K8s journey step title." },
  "journeys.k8s.verify.body": {
    defaultMessage: "Workload certificates appear in the inventory and rotate on their own — nothing static to steal.",
    description: "K8s journey step body.",
  },
  "journeys.devices.title": { defaultMessage: "Enroll devices", description: "Journey title: device enrollment." },
  "journeys.devices.description": {
    defaultMessage: "Network and embedded devices enroll over EST, SCEP, or CMP and renew before expiry.",
    description: "Journey description: device enrollment.",
  },
  "journeys.devices.protocols.title": { defaultMessage: "Inspect the enrollment registers", description: "Devices journey step title." },
  "journeys.devices.protocols.body": {
    defaultMessage: "EST, SCEP, and CMP registers, gates, and live responder status all live on the Protocols page.",
    description: "Devices journey step body.",
  },
  "journeys.devices.cacerts.title": { defaultMessage: "Fetch the CA chain", description: "Devices journey step title." },
  "journeys.devices.cacerts.body": {
    defaultMessage: "Devices bootstrap trust by fetching the CA chain from the EST well-known endpoint.",
    description: "Devices journey step body.",
  },
  "journeys.devices.enroll.title": { defaultMessage: "Enroll with a CSR", description: "Devices journey step title." },
  "journeys.devices.enroll.body": {
    defaultMessage: "POST the device CSR to simpleenroll; re-enroll before expiry with the same flow.",
    description: "Devices journey step body.",
  },
  "journeys.devices.bootstrap.title": { defaultMessage: "Gate constrained and MDM clients", description: "Devices journey step title." },
  "journeys.devices.bootstrap.body": {
    defaultMessage: "Tiny IoT clients use one-time bootstrap tokens; MDM phones are gated by SCEP challenge policies.",
    description: "Devices journey step body.",
  },
  "journeys.sec.title": { defaultMessage: "Manage secrets", description: "Journey title: secrets management." },
  "journeys.sec.description": {
    defaultMessage: "An encrypted store with versioning, short-lived credentials, one-time shares, scanning, and cloud sync.",
    description: "Journey description: secrets management.",
  },
  "journeys.sec.enable.title": { defaultMessage: "Enable the secrets surface", description: "Secrets journey step title." },
  "journeys.sec.enable.body": {
    defaultMessage: "Secrets are fail-closed until the surface is enabled and a key-encryption key file exists.",
    description: "Secrets journey step body.",
  },
  "journeys.sec.store.title": { defaultMessage: "Work the native store", description: "Secrets journey step title." },
  "journeys.sec.store.body": {
    defaultMessage: "Browse the tree, create, reveal-once, rotate, and delete — metadata is durable, values are not re-rendered.",
    description: "Secrets journey step body.",
  },
  "journeys.sec.engines.title": { defaultMessage: "Issue short-lived credentials", description: "Secrets journey step title." },
  "journeys.sec.engines.body": {
    defaultMessage: "Dynamic leases, PKI-as-a-secret, and transit/KMIP operations live under the Engines tab.",
    description: "Secrets journey step body.",
  },
  "journeys.sec.share.title": { defaultMessage: "Share without residue", description: "Secrets journey step title." },
  "journeys.sec.share.body": {
    defaultMessage: "One-time shares self-destruct on redemption; ephemeral API keys reveal once and expire on their own.",
    description: "Secrets journey step body.",
  },
  "journeys.sec.scan.title": { defaultMessage: "Scan for committed secrets", description: "Secrets journey step title." },
  "journeys.sec.scan.body": {
    defaultMessage: "Repository and third-party scans report redacted findings only — file, line, and fingerprint, never the value.",
    description: "Secrets journey step body.",
  },
  "journeys.sec.sync.title": { defaultMessage: "Sync to where workloads read", description: "Secrets journey step title." },
  "journeys.sec.sync.body": {
    defaultMessage: "Push stored secrets to cloud and CI targets; the browser only ever sends the name and remote key.",
    description: "Secrets journey step body.",
  },
  "journeys.ssh.title": { defaultMessage: "SSH at scale", description: "Journey title: SSH certificates at scale." },
  "journeys.ssh.description": {
    defaultMessage: "Replace standing SSH keys with short-lived certificates from a central CA, with revocation via KRL.",
    description: "Journey description: SSH at scale.",
  },
  "journeys.ssh.source.title": { defaultMessage: "Discover standing SSH access", description: "SSH journey step title." },
  "journeys.ssh.source.body": {
    defaultMessage: "An SSH discovery source finds authorized keys across the fleet — orphaned keys get flagged.",
    description: "SSH journey step body.",
  },
  "journeys.ssh.findings.title": { defaultMessage: "Review the key findings", description: "SSH journey step title." },
  "journeys.ssh.findings.body": {
    defaultMessage: "Triage discovered keys in the findings table before any host trusts the new CA.",
    description: "SSH journey step body.",
  },
  "journeys.ssh.trust.title": { defaultMessage: "Roll trust out to hosts", description: "SSH journey step title." },
  "journeys.ssh.trust.body": {
    defaultMessage: "The rollout records hosts, health checks, and the rollback plan as evidence; the SSH page tracks status.",
    description: "SSH journey step body.",
  },
  "journeys.ssh.issue.title": { defaultMessage: "Issue attested user certs", description: "SSH journey step title." },
  "journeys.ssh.issue.body": {
    defaultMessage: "Short-lived user certificates are gated on attestation, with principals and source addresses pinned.",
    description: "SSH journey step body.",
  },
  "journeys.ssh.revoke.title": { defaultMessage: "Revoke before expiry", description: "SSH journey step title." },
  "journeys.ssh.revoke.body": {
    defaultMessage: "Revocation lands in the KRL that hosts already fetch — no per-host key surgery.",
    description: "SSH journey step body.",
  },
  "journeys.ssh.retire.title": { defaultMessage: "Retire standing keys", description: "SSH journey step title." },
  "journeys.ssh.retire.body": {
    defaultMessage: "Once cert-based access holds, retire the standing keys and keep the rollout ledger as proof.",
    description: "SSH journey step body.",
  },
  "journeys.team.title": { defaultMessage: "Onboard a team", description: "Journey title: team onboarding." },
  "journeys.team.description": {
    defaultMessage: "An isolated tenant slice with SSO, roles, default-deny policy, and a signed audit trail.",
    description: "Journey description: team onboarding.",
  },
  "journeys.team.token.title": { defaultMessage: "Mint the tenant token", description: "Team journey step title." },
  "journeys.team.token.body": {
    defaultMessage: "A tenant-scoped token is the team's boundary: everything it touches stays inside the tenant.",
    description: "Team journey step body.",
  },
  "journeys.team.sso.title": { defaultMessage: "Wire browser SSO", description: "Team journey step title." },
  "journeys.team.sso.body": {
    defaultMessage: "OIDC, SAML, or LDAP config maps signed-in users to the tenant; SCIM keeps membership synced.",
    description: "Team journey step body.",
  },
  "journeys.team.roles.title": { defaultMessage: "Assign roles and tokens", description: "Team journey step title." },
  "journeys.team.roles.body": {
    defaultMessage: "Members, roles, API tokens, and offboarding are all administered on the Platform access tab.",
    description: "Team journey step body.",
  },
  "journeys.team.policy.title": { defaultMessage: "Turn on default-deny policy", description: "Team journey step title." },
  "journeys.team.policy.body": {
    defaultMessage: "Policy gates with dual control decide what issues; the Policy page explains every decision.",
    description: "Team journey step body.",
  },
  "journeys.team.audit.title": { defaultMessage: "Prove it with the audit trail", description: "Team journey step title." },
  "journeys.team.audit.body": {
    defaultMessage: "Query events in the console and export the signed evidence bundle for compliance.",
    description: "Team journey step body.",
  },
  "journeys.pqc.title": { defaultMessage: "Crypto agility & PQC", description: "Journey title: crypto agility and post-quantum." },
  "journeys.pqc.description": {
    defaultMessage: "Inventory your algorithms, pin the rules, and migrate quantum-vulnerable credentials deliberately.",
    description: "Journey description: crypto agility and PQC.",
  },
  "journeys.pqc.scan.title": { defaultMessage: "Queue a CBOM scan", description: "PQC journey step title." },
  "journeys.pqc.scan.body": {
    defaultMessage: "The scan inventories algorithms across TLS endpoints and host configs; Posture shows the results.",
    description: "PQC journey step body.",
  },
  "journeys.pqc.inventory.title": { defaultMessage: "Read your crypto posture", description: "PQC journey step title." },
  "journeys.pqc.inventory.body": {
    defaultMessage: "Posture grades PQC readiness and lists the quantum-vulnerable assets worth migrating first.",
    description: "PQC journey step body.",
  },
  "journeys.pqc.graph.title": { defaultMessage: "Trace crypto assets on the graph", description: "PQC journey step title." },
  "journeys.pqc.graph.body": {
    defaultMessage: "Crypto-asset nodes show which workloads and credentials share a vulnerable key.",
    description: "PQC journey step body.",
  },
  "journeys.pqc.profile.title": { defaultMessage: "Pin algorithms in a profile", description: "PQC journey step title." },
  "journeys.pqc.profile.body": {
    defaultMessage: "A profile restricts allowed key algorithms so nothing new is minted on the old curve.",
    description: "PQC journey step body.",
  },
  "journeys.pqc.migrate.title": { defaultMessage: "Migrate and rehearse rollback", description: "PQC journey step title." },
  "journeys.pqc.migrate.body": {
    defaultMessage: "The EE migration orchestrator moves assets to ML-DSA targets and can roll a run back — rehearse it.",
    description: "PQC journey step body.",
  },
  "journeys.prod.title": { defaultMessage: "Run in production", description: "Journey title: production readiness." },
  "journeys.prod.description": {
    defaultMessage: "A real certificate, live health, rehearsed recovery, exportable audit, and tuned backpressure.",
    description: "Journey description: production readiness.",
  },
  "journeys.prod.tls.title": { defaultMessage: "Serve over your own certificate", description: "Production journey step title." },
  "journeys.prod.tls.body": {
    defaultMessage: "Point the server at your certificate and key files before anything else depends on it.",
    description: "Production journey step body.",
  },
  "journeys.prod.health.title": { defaultMessage: "Watch readiness and metrics", description: "Production journey step title." },
  "journeys.prod.health.body": {
    defaultMessage: "readyz checks db, nats, and signer; Prometheus scrapes /metrics — System posture summarizes the runtime.",
    description: "Production journey step body.",
  },
  "journeys.prod.backup.title": { defaultMessage: "Rehearse backup and restore", description: "Production journey step title." },
  "journeys.prod.backup.body": {
    defaultMessage: "Encrypted full backups only count once a restore has actually been rehearsed.",
    description: "Production journey step body.",
  },
  "journeys.prod.audit.title": { defaultMessage: "Export audit evidence", description: "Production journey step title." },
  "journeys.prod.audit.body": {
    defaultMessage: "Query policy decisions in the console and export the signed bundle auditors can verify.",
    description: "Production journey step body.",
  },
  "journeys.prod.resilience.title": { defaultMessage: "Tune limits, federation, air-gap", description: "Production journey step title." },
  "journeys.prod.resilience.body": {
    defaultMessage: "Backpressure, passive-region federation, and air-gap mode are environment-driven; posture discloses their state.",
    description: "Production journey step body.",
  },
  "journeys.api.title": { defaultMessage: "Build on the API", description: "Journey title: API integration." },
  "journeys.api.description": {
    defaultMessage: "One OpenAPI contract, a CLI at full parity, idempotent mutations, and typed SDKs.",
    description: "Journey description: API integration.",
  },
  "journeys.api.contract.title": { defaultMessage: "Fetch the contract", description: "API journey step title." },
  "journeys.api.contract.body": {
    defaultMessage: "The OpenAPI 3.1 document is the source of truth; the API Explorer renders it live.",
    description: "API journey step body.",
  },
  "journeys.api.cli.title": { defaultMessage: "Drive it from the CLI", description: "API journey step title." },
  "journeys.api.cli.body": {
    defaultMessage: "The CLI covers every API operation — point it at the server with two environment variables.",
    description: "API journey step body.",
  },
  "journeys.api.idempotency.title": { defaultMessage: "Make mutations idempotent", description: "API journey step title." },
  "journeys.api.idempotency.body": {
    defaultMessage: "Send a stable Idempotency-Key with every create so retries never double-write.",
    description: "API journey step body.",
  },
  "journeys.api.graph.title": { defaultMessage: "Query the credential graph", description: "API journey step title." },
  "journeys.api.graph.body": {
    defaultMessage: "The same graph the console draws is queryable — nodes, edges, blast radius, reachability.",
    description: "API journey step body.",
  },
  "request.wizard.nextReview": {
    defaultMessage: "Next: review",
    description: "Request-credential wizard button from step 2 to step 3.",
  },
  "request.wizard.ownerHint": {
    defaultMessage: "Prefilled with your session principal.",
    description: "Hint under the owner-id field in the request wizard.",
  },
  "identities.decommission.description": {
    defaultMessage: "Retire or revoke identities in response to HR departures, vendor terminations, or inactivity windows.",
    description: "Description under the decommission-by-signal heading.",
  },
  "state.permissionDenied": {
    defaultMessage: "Permission denied",
    description: "Shared alert title for authenticated users who cannot read a resource.",
  },
  "grid.state.loading": {
    defaultMessage: "Loading rows...",
    description: "Shared data-grid loading state.",
  },
  "grid.state.error": {
    defaultMessage: "Could not load rows",
    description: "Shared data-grid error state title.",
  },
  "grid.state.permissionDeniedBody": {
    defaultMessage: "Your session cannot read these rows.",
    description: "Shared data-grid permission-denied body.",
  },
  "grid.state.unavailable": {
    defaultMessage: "Rows unavailable",
    description: "Shared data-grid unavailable state title.",
  },
  "grid.state.empty": {
    defaultMessage: "No rows",
    description: "Shared data-grid empty state title.",
  },
  "shell.primaryNavigation": {
    defaultMessage: "Primary",
    description: "Accessible label for the primary navigation landmark.",
  },
  "shell.primaryNavigationDialog": {
    defaultMessage: "Primary navigation",
    description: "Accessible name for the mobile navigation dialog.",
  },
  "shell.openPrimaryNavigation": {
    defaultMessage: "Open primary navigation",
    description: "Mobile navigation open button label.",
  },
  "shell.closePrimaryNavigation": {
    defaultMessage: "Close primary navigation",
    description: "Mobile navigation close button label.",
  },
  "shell.showPrimaryNavigation": {
    defaultMessage: "Show navigation sidebar",
    description: "Desktop navigation sidebar expand button label.",
  },
  "shell.hidePrimaryNavigation": {
    defaultMessage: "Hide navigation sidebar",
    description: "Desktop navigation sidebar collapse button label.",
  },
  "shell.navigation": {
    defaultMessage: "Navigation",
    description: "Mobile drawer title.",
  },
  "shell.openCommandPalette": {
    defaultMessage: "Open command palette",
    description: "Command palette trigger label.",
  },
  "shell.searchOrJump": {
    defaultMessage: "Search or jump",
    description: "Command palette compact trigger text.",
  },
  "shell.tenantContext": {
    defaultMessage: "Tenant context",
    description: "Accessible label for tenant context in the global header.",
  },
  "shell.tenant": {
    defaultMessage: "Tenant",
    description: "Tenant label in the global header.",
  },
  "shell.locale": {
    defaultMessage: "Language",
    description: "Header locale selector label.",
  },
  "shell.openKeyboardShortcuts": {
    defaultMessage: "Open keyboard shortcuts",
    description: "Keyboard-shortcuts help button label.",
  },
  "shell.signOut": {
    defaultMessage: "Sign out",
    description: "Button label for ending the current browser session.",
  },
  "shell.signOutFailed": {
    defaultMessage: "Sign-out failed",
    description: "Short error shown when the current browser session could not be ended.",
  },
  "shell.routeAnnouncement": {
    defaultMessage: "Navigated to {page}",
    description: "Live-region announcement after a single-page navigation moves focus to the new page.",
  },
  "locale.enUS": {
    defaultMessage: "English (United States)",
    description: "Locale selector label for en-US.",
  },
  "locale.esES": {
    defaultMessage: "Spanish (Spain)",
    description: "Locale selector label for es-ES.",
  },
  "locale.enXA": {
    defaultMessage: "English pseudo-locale",
    description: "Locale selector label for the LTR pseudo-locale.",
  },
  "locale.arXB": {
    defaultMessage: "RTL pseudo-locale",
    description: "Locale selector label for the RTL pseudo-locale.",
  },
  "nav.section.needsAction": {
    defaultMessage: "Needs action",
    description: "Primary nav section for urgent worklists.",
  },
  "nav.section.needsActionWorklists": {
    defaultMessage: "Needs action worklists",
    description: "Accessible label for the urgent worklist list.",
  },
  "nav.task.expiringSoon.label": {
    defaultMessage: "Expiring soon",
    description: "Certificate-expiry worklist navigation label.",
  },
  "nav.task.expiringSoon.description": {
    defaultMessage: "30-day certificate worklist",
    description: "Certificate-expiry worklist navigation description.",
  },
  "nav.task.pendingApprovals.label": {
    defaultMessage: "Pending approvals",
    description: "Approval inbox worklist navigation label.",
  },
  "nav.task.pendingApprovals.description": {
    defaultMessage: "dual-control issue, rotate, and revoke inbox",
    description: "Approval inbox worklist navigation description.",
  },
  "nav.task.highestRisk.label": {
    defaultMessage: "Highest risk",
    description: "Risk worklist navigation label.",
  },
  "nav.task.highestRisk.description": {
    defaultMessage: "risk-prioritized rotation list",
    description: "Risk worklist navigation description.",
  },
  "certificates.health.heading": {
    defaultMessage: "Estate certificate health",
    description: "Heading for the certificate estate expiry and source-health panel.",
  },
  "certificates.health.description": {
    defaultMessage: "Includes issued, imported, and discovery-fed certificate inventory.",
    description: "Short description for the certificate estate health panel.",
  },
  "breakglass.issue.heading": {
    defaultMessage: "Online break-glass issue",
    description: "Heading for the online break-glass issue form.",
  },
  "breakglass.issue.description": {
    defaultMessage: "Submit a CSR, reason, TTL, and m-of-n operator approvals; the server records breakglass.issued before returning the bundle.",
    description: "Description for the online break-glass issue form.",
  },
  "breakglass.issue.label": {
    defaultMessage: "Online issue request (JSON)",
    description: "Textarea label for an online break-glass issue request body.",
  },
  "breakglass.issue.submit": {
    defaultMessage: "Issue break-glass certificate",
    description: "Submit button for online break-glass issue.",
  },
  "breakglass.issue.busy": {
    defaultMessage: "Issuing...",
    description: "Busy submit button text for online break-glass issue.",
  },
  "breakglass.issue.errorTitle": {
    defaultMessage: "Issue failed",
    description: "Error title for online break-glass issue failures.",
  },
  "breakglass.issue.invalidJson": {
    defaultMessage: "Issue request must be one JSON object.",
    description: "Validation error when the online break-glass issue request is not valid JSON.",
  },
  "breakglass.issue.status": {
    defaultMessage: "Issued and audited {count} break-glass bundle.",
    description: "Success status after issuing an online break-glass bundle.",
  },
  "certificates.health.stateCritical": {
    defaultMessage: "critical",
    description: "Critical certificate health state label.",
  },
  "certificates.health.stateWarning": {
    defaultMessage: "warning",
    description: "Warning certificate health state label.",
  },
  "certificates.health.stateOk": {
    defaultMessage: "ok",
    description: "Healthy certificate health state label.",
  },
  "certificates.health.totalInventory": {
    defaultMessage: "Total inventory",
    description: "Certificate health summary label for total inventory.",
  },
  "certificates.health.expiring7d": {
    defaultMessage: "Expiring 7d",
    description: "Certificate health summary label for certificates expiring within seven days.",
  },
  "certificates.health.expiring30d": {
    defaultMessage: "Expiring 30d",
    description: "Certificate health summary label for certificates expiring within thirty days.",
  },
  "certificates.health.externalSources": {
    defaultMessage: "External sources",
    description: "Certificate health summary label for non-trstctl-issued certificate sources.",
  },
  "certificates.health.sourcePosture": {
    defaultMessage: "Source posture",
    description: "Heading for the certificate health source breakdown.",
  },
  "certificates.health.external": {
    defaultMessage: "external",
    description: "Badge label for imported or discovery-fed certificate sources.",
  },
  "certificates.health.issued": {
    defaultMessage: "issued",
    description: "Badge label for trstctl-issued certificate sources.",
  },
  "certificates.health.soonestExpirations": {
    defaultMessage: "Soonest expirations",
    description: "Heading for the soonest-expiring certificate list.",
  },
  "certificates.health.no90dExpirations": {
    defaultMessage: "No certificates expire inside the 90-day estate window.",
    description: "Empty state for the certificate health soonest-expiring list.",
  },
  "certificates.crl.heading": {
    defaultMessage: "CRL distribution",
    description: "Heading for the certificate revocation-list distribution panel.",
  },
  "certificates.crl.summary": {
    defaultMessage: "CAs: {caCount}; shards: {shardCount}; revoked serials: {revokedCount}.",
    description: "Summary of currently published CRL distribution artifacts.",
  },
  "certificates.crl.empty": {
    defaultMessage: "No CRL artifacts have been published yet.",
    description: "Empty state for CRL distribution artifacts.",
  },
  "certificates.crl.shardPlan": {
    defaultMessage: "{shardCount}-way shard plan",
    description: "Badge showing the current planned CRL shard count.",
  },
  "certificates.crl.awaiting": {
    defaultMessage: "Awaiting CRL",
    description: "Badge shown before the first CRL artifact is published.",
  },
  "certificates.crl.ca": {
    defaultMessage: "CA",
    description: "CRL distribution table column header for the CA identifier.",
  },
  "certificates.crl.full": {
    defaultMessage: "Full CRL",
    description: "CRL distribution table column header for the full CRL artifact.",
  },
  "certificates.crl.shards": {
    defaultMessage: "Shards",
    description: "CRL distribution table column header for shard artifacts.",
  },
  "certificates.crl.delta": {
    defaultMessage: "Delta",
    description: "CRL distribution table column header for delta CRL artifacts.",
  },
  "certificates.crl.window": {
    defaultMessage: "Window",
    description: "CRL distribution table column header for the publication freshness window.",
  },
  "certificates.crl.revokedCount": {
    defaultMessage: "{count} revoked",
    description: "CRL distribution row label for revoked serial count.",
  },
  "certificates.crl.servedCount": {
    defaultMessage: "{count} available",
    description: "CRL distribution row label for available shard count.",
  },
  "certificates.crl.plannedCount": {
    defaultMessage: "{count} planned",
    description: "CRL distribution row label for planned shard count.",
  },
  "certificates.crl.deltaBase": {
    defaultMessage: "base #{base}",
    description: "CRL distribution row label for a delta CRL base number.",
  },
  "certificates.crl.nextUpdate": {
    defaultMessage: "next {date}",
    description: "CRL distribution row label for the next-update timestamp.",
  },
  "certificates.ct.heading": {
    defaultMessage: "Certificate Transparency",
    description: "Heading for the Certificate Transparency submission panel.",
  },
  "certificates.ct.queuedBadge": {
    defaultMessage: "{capability} queued {queued}",
    description: "Badge summarizing queued Certificate Transparency submissions.",
  },
  "certificates.ct.certificatePEM": {
    defaultMessage: "Certificate PEM",
    description: "Label for the final certificate PEM field in the CT submission form.",
  },
  "certificates.ct.precertificatePEM": {
    defaultMessage: "Precertificate PEM",
    description: "Label for the precertificate PEM field in the CT submission form.",
  },
  "certificates.ct.chainPEM": {
    defaultMessage: "Issuer chain PEM",
    description: "Label for the issuer chain PEM field in the CT submission form.",
  },
  "certificates.ct.chainPlaceholder": {
    defaultMessage: "optional",
    description: "Placeholder for the optional issuer chain PEM field in the CT submission form.",
  },
  "certificates.ct.logs": {
    defaultMessage: "CT logs",
    description: "Label for CT log URL input.",
  },
  "certificates.ct.logsPlaceholder": {
    defaultMessage: "https://ct.example.com",
    description: "Placeholder CT log URL in the CT submission form.",
  },
  "certificates.ct.allowPrivate": {
    defaultMessage: "Allow private log endpoint",
    description: "Checkbox label for allowing a private CT log endpoint.",
  },
  "certificates.ct.queueing": {
    defaultMessage: "Queueing...",
    description: "Busy button label while a CT submission is queueing.",
  },
  "certificates.ct.queue": {
    defaultMessage: "Queue CT submission",
    description: "Submit button label for the CT submission form.",
  },
  "certificates.ct.errorTitle": {
    defaultMessage: "Could not queue CT submission",
    description: "Error-state heading for a failed CT submission.",
  },
  "certificates.ct.acceptedOne": {
    defaultMessage: "{count} log target accepted.",
    description: "Success status when one CT log target accepted the queued submission.",
  },
  "certificates.ct.acceptedMany": {
    defaultMessage: "{count} log targets accepted.",
    description: "Success status when multiple CT log targets accepted the queued submission.",
  },
  "certificates.ct.errorCertificateRequired": {
    defaultMessage: "Certificate PEM is required.",
    description: "Validation error when the CT submission form has no certificate PEM.",
  },
  "certificates.ct.errorLogRequired": {
    defaultMessage: "At least one CT log is required.",
    description: "Validation error when the CT submission form has no CT log URL.",
  },
  "certificates.ct.action": {
    defaultMessage: "queue Certificate Transparency submission",
    description: "Action phrase used in CT submission error messages.",
  },
  "certificates.rogue.heading": {
    defaultMessage: "Rogue certificate detection",
    description: "Heading for the rogue and non-compliant certificate posture panel.",
  },
  "certificates.rogue.description": {
    defaultMessage: "Flags unexpected Certificate Transparency hits and active certificates that fall outside key, lifetime, owner, or issuer policy.",
    description: "Short description for rogue and non-compliant certificate detection.",
  },
  "certificates.rogue.findingBadge": {
    defaultMessage: "{count} findings",
    description: "Badge summarizing rogue certificate findings.",
  },
  "certificates.rogue.metricRogue": {
    defaultMessage: "Rogue",
    description: "Summary metric label for rogue certificate findings.",
  },
  "certificates.rogue.metricNonCompliant": {
    defaultMessage: "Non-compliant",
    description: "Summary metric label for non-compliant certificate findings.",
  },
  "certificates.rogue.metricCT": {
    defaultMessage: "CT hits",
    description: "Summary metric label for unexpected Certificate Transparency hits.",
  },
  "certificates.rogue.metricHigh": {
    defaultMessage: "High or critical",
    description: "Summary metric label for high or critical rogue certificate findings.",
  },
  "certificates.rogue.empty": {
    defaultMessage: "No rogue or non-compliant certificates found in the current posture.",
    description: "Empty state for the rogue certificate posture panel.",
  },
  "certificates.rogue.caption": {
    defaultMessage: "Rogue and non-compliant certificate findings",
    description: "Accessible table caption for rogue and non-compliant certificate findings.",
  },
  "certificates.rogue.columnSubject": {
    defaultMessage: "Subject",
    description: "Rogue certificate findings table column for certificate subject.",
  },
  "certificates.rogue.columnStatus": {
    defaultMessage: "Status",
    description: "Rogue certificate findings table column for policy status.",
  },
  "certificates.rogue.columnSeverity": {
    defaultMessage: "Severity",
    description: "Rogue certificate findings table column for severity.",
  },
  "certificates.rogue.columnEvidence": {
    defaultMessage: "Evidence",
    description: "Rogue certificate findings table column for evidence references.",
  },
  "certificates.rogue.columnRecommendation": {
    defaultMessage: "Recommendation",
    description: "Rogue certificate findings table column for remediation guidance.",
  },
  "certificates.rogue.policyRogue": {
    defaultMessage: "Rogue",
    description: "Policy status label for a rogue certificate finding.",
  },
  "certificates.rogue.policyNonCompliant": {
    defaultMessage: "Non-compliant",
    description: "Policy status label for a non-compliant certificate finding.",
  },
  "certificates.rogue.typeCTUnexpected": {
    defaultMessage: "Unexpected CT issuance",
    description: "Finding type label for unexpected Certificate Transparency issuance.",
  },
  "certificates.rogue.typeNotInInventory": {
    defaultMessage: "Not in inventory",
    description: "Finding type label for a certificate observed outside inventory.",
  },
  "certificates.rogue.typeWeakKey": {
    defaultMessage: "Weak key",
    description: "Finding type label for a weak certificate key algorithm.",
  },
  "certificates.rogue.typeLifetime": {
    defaultMessage: "Lifetime exceeds policy",
    description: "Finding type label for a certificate lifetime that exceeds policy.",
  },
  "certificates.rogue.typeExpiredActive": {
    defaultMessage: "Expired while active",
    description: "Finding type label for an active certificate past NotAfter.",
  },
  "certificates.rogue.typeOwnerMissing": {
    defaultMessage: "Owner missing",
    description: "Finding type label for a certificate without an owner.",
  },
  "certificates.rogue.typeIssuerMissing": {
    defaultMessage: "Issuer missing",
    description: "Finding type label for a certificate without issuer metadata.",
  },
  "certificates.rogue.riskScore": {
    defaultMessage: "{score} risk",
    description: "Risk score label for a rogue certificate finding.",
  },
  "nav.group.overview": {
    defaultMessage: "Overview",
    description: "Primary navigation group.",
  },
  "nav.group.inventoryDiscovery": {
    defaultMessage: "Discover & inventory",
    description: "Primary navigation group.",
  },
  "nav.group.issuanceCas": {
    defaultMessage: "Issue & renew",
    description: "Primary navigation group.",
  },
  "nav.group.protocols": {
    defaultMessage: "Protocols",
    description: "Primary navigation group.",
  },
  "nav.group.secrets": {
    defaultMessage: "Secrets",
    description: "Primary navigation group.",
  },
  "nav.group.connectorsPlugins": {
    defaultMessage: "Connectors & Plugins",
    description: "Primary navigation group.",
  },
  "nav.group.riskInsight": {
    defaultMessage: "Monitor posture",
    description: "Primary navigation group.",
  },
  "nav.group.incidentsJit": {
    defaultMessage: "Approve & respond",
    description: "Primary navigation group.",
  },
  "nav.group.governance": {
    defaultMessage: "Governance",
    description: "Primary navigation group.",
  },
  "nav.group.platform": {
    defaultMessage: "Administer",
    description: "Primary navigation group.",
  },
  "nav.item.dashboard": {
    defaultMessage: "Dashboard",
    description: "Primary navigation item.",
  },
  "nav.item.setUp": {
    defaultMessage: "Set up",
    description: "Primary navigation item.",
  },
  "nav.item.requestCredential": {
    defaultMessage: "Request credential",
    description: "Primary navigation item.",
  },
  "nav.item.certificates": {
    defaultMessage: "Certificates",
    description: "Primary navigation item.",
  },
  "nav.item.identities": {
    defaultMessage: "Identities",
    description: "Primary navigation item.",
  },
  "nav.item.owners": {
    defaultMessage: "Owners",
    description: "Primary navigation item.",
  },
  "nav.item.agents": {
    defaultMessage: "Agents",
    description: "Primary navigation item.",
  },
  "nav.item.discovery": {
    defaultMessage: "Discovery",
    description: "Primary navigation item.",
  },
  "nav.item.workloads": {
    defaultMessage: "Workloads",
    description: "Primary navigation item.",
  },
  "nav.item.profiles": {
    defaultMessage: "Certificate profiles",
    description: "Primary navigation item.",
  },
  "nav.item.issuance": {
    defaultMessage: "Issuance",
    description: "Primary navigation item.",
  },
  "nav.item.caHierarchy": {
    defaultMessage: "CA hierarchy",
    description: "Primary navigation item.",
  },
  "caHierarchy.discovery.heading": {
    defaultMessage: "CA discovery inventory",
    description: "Heading for the CA hierarchy direct-CA discovery inventory panel.",
  },
  "caHierarchy.discovery.description": {
    defaultMessage: "Public upstream CAs, private upstream CAs, and imported CA hierarchy authorities are normalized into one read-only inventory.",
    description: "Short description for the direct-CA discovery inventory panel.",
  },
  "caHierarchy.discovery.summaryPublic": {
    defaultMessage: "Public",
    description: "Summary label for public CAs in the direct-CA discovery inventory.",
  },
  "caHierarchy.discovery.summaryPrivate": {
    defaultMessage: "Private",
    description: "Summary label for private CAs in the direct-CA discovery inventory.",
  },
  "caHierarchy.discovery.summaryUpstream": {
    defaultMessage: "Upstream",
    description: "Summary label for configured upstream CAs in the direct-CA discovery inventory.",
  },
  "caHierarchy.discovery.summaryAuthorities": {
    defaultMessage: "Authorities",
    description: "Summary label for imported hierarchy authorities in the direct-CA discovery inventory.",
  },
  "caHierarchy.discovery.emptyTitle": {
    defaultMessage: "No CAs discovered",
    description: "Empty-state title for the direct-CA discovery inventory.",
  },
  "caHierarchy.discovery.emptyBody": {
    defaultMessage: "Connect an upstream CA or import an authority to populate the inventory.",
    description: "Empty-state body for the direct-CA discovery inventory.",
  },
  "caHierarchy.discovery.columnName": {
    defaultMessage: "Name",
    description: "Table column label for discovered CA name.",
  },
  "caHierarchy.discovery.columnScope": {
    defaultMessage: "Scope",
    description: "Table column label for discovered CA public/private scope.",
  },
  "caHierarchy.discovery.columnSource": {
    defaultMessage: "Source",
    description: "Table column label for discovered CA source.",
  },
  "caHierarchy.discovery.columnStatus": {
    defaultMessage: "Status",
    description: "Table column label for discovered CA status.",
  },
  "caHierarchy.discovery.columnServedPath": {
    defaultMessage: "Runtime path",
    description: "Table column label for the API path associated with a discovered CA.",
  },
  "caHierarchy.discovery.scopePublic": {
    defaultMessage: "Public",
    description: "Scope label for public CAs.",
  },
  "caHierarchy.discovery.scopePrivate": {
    defaultMessage: "Private",
    description: "Scope label for private CAs.",
  },
  "caHierarchy.discovery.sourceExternal": {
    defaultMessage: "External CA registry",
    description: "Source label for CAs configured in the upstream CA registry.",
  },
  "caHierarchy.discovery.sourceHierarchy": {
    defaultMessage: "CA hierarchy",
    description: "Source label for CAs stored in the private CA hierarchy.",
  },
  "caHierarchy.discovery.signerBacked": {
    defaultMessage: "signer-backed",
    description: "Small status label for discovered authorities with a signer-held key handle.",
  },
  "caHierarchy.externalIssue.heading": {
    defaultMessage: "Outbound external CA issuance",
    description: "Heading for the external CA issuance panel.",
  },
  "caHierarchy.externalIssue.description": {
    defaultMessage:
      "Submit a CSR through a configured upstream CA. The browser shows outbox-pending while the server records the CA issue intent, then shows issued evidence without rendering the certificate PEM.",
    description: "Short description for the external CA issuance panel.",
  },
  "caHierarchy.externalIssue.emptyTitle": {
    defaultMessage: "No external CAs configured",
    description: "Empty-state title when no external CA registry entries are available.",
  },
  "caHierarchy.externalIssue.emptyBody": {
    defaultMessage: "Configure an upstream CA before issuing through the external CA registry.",
    description: "Empty-state body when no external CA registry entries are available.",
  },
  "caHierarchy.externalIssue.formHeading": {
    defaultMessage: "Registry-backed issue",
    description: "Heading for the external CA issuance form.",
  },
  "caHierarchy.externalIssue.submit": {
    defaultMessage: "Issue through external CA",
    description: "Button label for issuing a CSR through an external CA.",
  },
  "caHierarchy.externalIssue.errorTitle": {
    defaultMessage: "External CA issuance failed",
    description: "Error title for external CA issuance failures.",
  },
  "caHierarchy.externalIssue.caLabel": {
    defaultMessage: "External CA",
    description: "Label for selecting an external CA.",
  },
  "caHierarchy.externalIssue.caPlaceholder": {
    defaultMessage: "Select external CA",
    description: "Placeholder option for selecting an external CA.",
  },
  "caHierarchy.externalIssue.commonNameLabel": {
    defaultMessage: "Certificate common name",
    description: "Label for the requested certificate common name.",
  },
  "caHierarchy.externalIssue.dnsNamesLabel": {
    defaultMessage: "DNS names",
    description: "Label for requested DNS SANs.",
  },
  "caHierarchy.externalIssue.dnsNamesPlaceholder": {
    defaultMessage: "service.example.com, alt.example.com",
    description: "Placeholder for requested DNS SANs.",
  },
  "caHierarchy.externalIssue.profileLabel": {
    defaultMessage: "Profile name",
    description: "Label for optional external CA profile name.",
  },
  "caHierarchy.externalIssue.profilePlaceholder": {
    defaultMessage: "web-server",
    description: "Placeholder for optional external CA profile name.",
  },
  "caHierarchy.externalIssue.ttlLabel": {
    defaultMessage: "TTL days",
    description: "Label for requested external CA certificate lifetime.",
  },
  "caHierarchy.externalIssue.csrLabel": {
    defaultMessage: "CSR PEM",
    description: "Label for the certificate signing request PEM.",
  },
  "caHierarchy.externalIssue.csrPlaceholder": {
    defaultMessage: "-----BEGIN CERTIFICATE REQUEST-----",
    description: "Placeholder for certificate signing request PEM input.",
  },
  "caHierarchy.externalIssue.statusHeading": {
    defaultMessage: "Issuance state",
    description: "Heading for the external CA issuance result state.",
  },
  "caHierarchy.externalIssue.stateLabel": {
    defaultMessage: "State",
    description: "Label for the external CA issuance state value.",
  },
  "caHierarchy.externalIssue.state.outboxPending": {
    defaultMessage: "outbox-pending",
    description: "State label while external CA issuance intent is pending delivery.",
  },
  "caHierarchy.externalIssue.state.externalCAIssued": {
    defaultMessage: "external-ca-issued",
    description: "State label after external CA issuance succeeds.",
  },
  "caHierarchy.externalIssue.pathLabel": {
    defaultMessage: "API path",
    description: "Label for the external CA issuance served API path.",
  },
  "caHierarchy.externalIssue.serialLabel": {
    defaultMessage: "Serial",
    description: "Label for the issued certificate serial.",
  },
  "caHierarchy.externalIssue.issuerLabel": {
    defaultMessage: "Issuer",
    description: "Label for the issued certificate issuer.",
  },
  "caHierarchy.externalIssue.notAfterLabel": {
    defaultMessage: "Not after",
    description: "Label for the issued certificate expiration timestamp.",
  },
  "discovery.monitoring.heading": {
    defaultMessage: "Continuous monitoring",
    description: "Heading for the discovery continuous monitoring posture panel.",
  },
  "discovery.monitoring.metricSources": {
    defaultMessage: "Sources",
    description: "Metric label for total discovery monitoring sources.",
  },
  "discovery.monitoring.metricScheduled": {
    defaultMessage: "Scheduled",
    description: "Metric label for sources with enabled monitoring schedules.",
  },
  "discovery.monitoring.metricActive": {
    defaultMessage: "Active",
    description: "Metric label for active continuous monitoring sources.",
  },
  "discovery.monitoring.metricRuns": {
    defaultMessage: "Runs",
    description: "Metric label for completed discovery monitoring runs.",
  },
  "discovery.monitoring.metricFindings": {
    defaultMessage: "Findings",
    description: "Metric label for discovery findings.",
  },
  "discovery.monitoring.metricInventory": {
    defaultMessage: "Inventory",
    description: "Metric label for certificate inventory rows from discovery.",
  },
  "discovery.monitoring.emptyTitle": {
    defaultMessage: "No monitored sources",
    description: "Empty-state title when no discovery monitoring sources exist.",
  },
  "discovery.monitoring.createSource": {
    defaultMessage: "Create source",
    description: "Button label to create a discovery source from the monitoring panel.",
  },
  "discovery.monitoring.emptyBody": {
    defaultMessage: "Add a source and schedule to start continuous monitoring.",
    description: "Empty-state body for the discovery monitoring panel.",
  },
  "discovery.monitoring.caption": {
    defaultMessage: "Continuous monitoring repository posture",
    description: "Accessible table caption for the monitoring repository posture table.",
  },
  "discovery.monitoring.columnSource": {
    defaultMessage: "Source",
    description: "Column header for the monitored source name.",
  },
  "discovery.monitoring.columnSchedule": {
    defaultMessage: "Schedule",
    description: "Column header for monitoring schedule status.",
  },
  "discovery.monitoring.columnLastRun": {
    defaultMessage: "Last run",
    description: "Column header for latest discovery run status.",
  },
  "discovery.monitoring.columnFindings": {
    defaultMessage: "Findings",
    description: "Column header for discovery finding counts.",
  },
  "discovery.monitoring.columnInventory": {
    defaultMessage: "Inventory",
    description: "Column header for certificate inventory counts.",
  },
  "discovery.monitoring.columnRepository": {
    defaultMessage: "Repository",
    description: "Column header for served repository API paths.",
  },
  "discovery.monitoring.unscheduled": {
    defaultMessage: "unscheduled",
    description: "Short status text for sources without an enabled monitoring schedule.",
  },
  "discovery.sourceForm.csvReadFailed": {
    defaultMessage: "Could not read CSV upload.",
    description: "Fallback error shown when a discovery source CSV file cannot be read.",
  },
  "discovery.shadow.heading": {
    defaultMessage: "Shadow NHI posture",
    description: "Heading for shadow and unmanaged non-human identity posture.",
  },
  "discovery.shadow.metricFindings": {
    defaultMessage: "Findings",
    description: "Shadow NHI posture metric for current findings.",
  },
  "discovery.shadow.metricUnmanaged": {
    defaultMessage: "Unmanaged",
    description: "Shadow NHI posture metric for unmanaged findings.",
  },
  "discovery.shadow.metricUnregistered": {
    defaultMessage: "Unregistered",
    description: "Shadow NHI posture metric for findings not linked to a managed identity.",
  },
  "discovery.shadow.metricOwnerless": {
    defaultMessage: "Ownerless",
    description: "Shadow NHI posture metric for findings without owner metadata.",
  },
  "discovery.shadow.metricHigh": {
    defaultMessage: "High or critical",
    description: "Shadow NHI posture metric for high or critical findings.",
  },
  "discovery.shadow.metricAnalyzed": {
    defaultMessage: "Analyzed",
    description: "Shadow NHI posture metric for analyzed discovery findings.",
  },
  "discovery.shadow.kindBreakdown": {
    defaultMessage: "Kind breakdown",
    description: "Heading for shadow NHI posture kind counts.",
  },
  "discovery.shadow.surfaceBreakdown": {
    defaultMessage: "Surface breakdown",
    description: "Heading for shadow NHI posture surface counts.",
  },
  "discovery.shadow.caption": {
    defaultMessage: "Shadow NHI findings",
    description: "Accessible table caption for shadow NHI findings.",
  },
  "discovery.shadow.columnSurface": {
    defaultMessage: "Surface",
    description: "Column header for shadow NHI discovery surface.",
  },
  "discovery.shadow.columnSeverity": {
    defaultMessage: "Severity",
    description: "Column header for shadow NHI severity.",
  },
  "discovery.shadow.columnRecommendation": {
    defaultMessage: "Recommendation",
    description: "Column header for shadow NHI recommendation.",
  },
  "discovery.shadow.empty": {
    defaultMessage: "No shadow NHI findings.",
    description: "Empty table text when no shadow NHI posture findings exist.",
  },
  "discovery.findings.filters": {
    defaultMessage: "Discovery finding filters",
    description: "Accessible label for discovery finding triage filters.",
  },
  "discovery.findings.filterStatus": {
    defaultMessage: "Triage status",
    description: "Label for the discovery finding triage-status filter.",
  },
  "discovery.findings.filterStatusAll": {
    defaultMessage: "All statuses",
    description: "Option label showing all discovery finding triage statuses.",
  },
  "discovery.findings.filterOwner": {
    defaultMessage: "Owner",
    description: "Label for the discovery finding owner filter.",
  },
  "discovery.findings.filterOwnerAll": {
    defaultMessage: "All owners",
    description: "Option label showing all discovery finding owners.",
  },
  "discovery.findings.filterTeam": {
    defaultMessage: "Team",
    description: "Label for the discovery finding team filter.",
  },
  "discovery.findings.filterTeamAll": {
    defaultMessage: "All teams",
    description: "Option label showing all discovery finding teams.",
  },
  "discovery.findings.filterTag": {
    defaultMessage: "Tag",
    description: "Label for the discovery finding tag filter.",
  },
  "discovery.findings.filterTagAll": {
    defaultMessage: "All tags",
    description: "Option label showing all discovery finding tags.",
  },
  "discovery.findings.caption": {
    defaultMessage: "Discovery findings",
    description: "Accessible table caption for discovery findings.",
  },
  "discovery.findings.columnStatus": {
    defaultMessage: "Status",
    description: "Column header for discovery finding triage status.",
  },
  "discovery.findings.columnKind": {
    defaultMessage: "Kind",
    description: "Column header for discovery finding kind.",
  },
  "discovery.findings.columnReference": {
    defaultMessage: "Reference",
    description: "Column header for discovery finding reference.",
  },
  "discovery.findings.columnOwner": {
    defaultMessage: "Owner",
    description: "Column header for discovery finding owner.",
  },
  "discovery.findings.columnTeam": {
    defaultMessage: "Team",
    description: "Column header for discovery finding team.",
  },
  "discovery.findings.columnTags": {
    defaultMessage: "Tags",
    description: "Column header for discovery finding tags.",
  },
  "discovery.findings.columnSource": {
    defaultMessage: "Source",
    description: "Column header for discovery finding source.",
  },
  "discovery.findings.columnRisk": {
    defaultMessage: "Risk",
    description: "Column header for discovery finding risk score.",
  },
  "discovery.findings.columnDiscovered": {
    defaultMessage: "Discovered",
    description: "Column header for discovery finding discovery time.",
  },
  "discovery.findings.columnActions": {
    defaultMessage: "Actions",
    description: "Column header for discovery finding action buttons.",
  },
  "discovery.findings.columnFingerprint": {
    defaultMessage: "Fingerprint",
    description: "Detail label for a discovery finding fingerprint.",
  },
  "discovery.findings.noMatches": {
    defaultMessage: "No findings match these filters.",
    description: "Empty row text when discovery finding filters hide every row.",
  },
  "discovery.findings.details": {
    defaultMessage: "Details",
    description: "Button label to open discovery finding details.",
  },
  "discovery.findings.claim": {
    defaultMessage: "Claim",
    description: "Button label to claim a discovery finding as managed.",
  },
  "discovery.findings.dismiss": {
    defaultMessage: "Dismiss",
    description: "Button label to dismiss a discovery finding.",
  },
  "discovery.findings.rotate": {
    defaultMessage: "Rotate",
    description: "Button label to rotate a managed identity from a discovery finding.",
  },
  "discovery.findings.revoke": {
    defaultMessage: "Revoke",
    description: "Button label to revoke a managed identity from a discovery finding.",
  },
  "discovery.findings.decommission": {
    defaultMessage: "Decommission",
    description: "Button label to decommission a managed NHI from a discovery finding.",
  },
  "discovery.findings.remediate": {
    defaultMessage: "Remediate",
    description: "Button label to run a remediation playbook from a discovery finding.",
  },
  "discovery.findings.detailHeading": {
    defaultMessage: "Finding detail",
    description: "Heading for the discovery finding detail panel.",
  },
  "discovery.findings.close": {
    defaultMessage: "Close",
    description: "Button label to close the discovery finding detail panel.",
  },
  "discovery.findings.triageReason": {
    defaultMessage: "Reason",
    description: "Label for a discovery finding triage reason.",
  },
  "discovery.findings.managedIdentity": {
    defaultMessage: "Managed identity",
    description: "Label for the managed identity associated with a discovery finding.",
  },
  "discovery.findings.claimSubmit": {
    defaultMessage: "Claim as managed",
    description: "Submit button label for claiming a discovery finding.",
  },
  "discovery.findings.dismissSubmit": {
    defaultMessage: "Dismiss finding",
    description: "Submit button label for dismissing a discovery finding.",
  },
  "discovery.findings.claimError": {
    defaultMessage: "Could not claim discovery finding",
    description: "Error fallback when claiming a discovery finding fails.",
  },
  "discovery.findings.dismissError": {
    defaultMessage: "Could not dismiss discovery finding",
    description: "Error fallback when dismissing a discovery finding fails.",
  },
  "discovery.findings.identityRequired": {
    defaultMessage: "Claim this finding to a managed identity before running lifecycle actions.",
    description: "Error shown when a discovery finding lacks a managed identity for lifecycle actions.",
  },
  "discovery.findings.actionError": {
    defaultMessage: "Could not run the discovery finding action",
    description: "Error fallback when running a discovery finding lifecycle action fails.",
  },
  "discovery.findings.rotateQueued": {
    defaultMessage: "Rotation playbook started for {ref}.",
    description: "Success text after starting a discovery finding rotation playbook.",
  },
  "discovery.findings.revokeQueued": {
    defaultMessage: "Revocation requested for {ref}.",
    description: "Success text after revoking a discovery finding identity.",
  },
  "discovery.findings.decommissionQueued": {
    defaultMessage: "Decommission requested for {ref}.",
    description: "Success text after starting NHI decommission from a discovery finding.",
  },
  "discovery.findings.remediationQueued": {
    defaultMessage: "Remediation playbook started for {ref}.",
    description: "Success text after starting a discovery finding remediation playbook.",
  },
  "discovery.findings.statusUnmanaged": {
    defaultMessage: "Unmanaged",
    description: "Triage status label for an unmanaged discovery finding.",
  },
  "discovery.findings.statusInvestigating": {
    defaultMessage: "Investigating",
    description: "Triage status label for a discovery finding under investigation.",
  },
  "discovery.findings.statusManaged": {
    defaultMessage: "Managed",
    description: "Triage status label for a managed discovery finding.",
  },
  "discovery.findings.statusDismissed": {
    defaultMessage: "Dismissed",
    description: "Triage status label for a dismissed discovery finding.",
  },
  "caHierarchy.offline.heading": {
    defaultMessage: "Offline root",
    description: "Heading for the CA hierarchy offline root workflow.",
  },
  "caHierarchy.offline.description": {
    defaultMessage: "Import a public root, generate a signer-held intermediate CSR, and import the root-signed intermediate.",
    description: "Short description for the offline root workflow.",
  },
  "caHierarchy.offline.errorTitle": {
    defaultMessage: "Offline-root action failed",
    description: "Error title for failed offline root workflow actions.",
  },
  "caHierarchy.offline.rootImport": {
    defaultMessage: "Root import",
    description: "Subheading for the offline root import panel.",
  },
  "caHierarchy.offline.startRootCeremony": {
    defaultMessage: "Start offline-root ceremony",
    description: "Button label for opening an offline root import ceremony.",
  },
  "caHierarchy.offline.importRoot": {
    defaultMessage: "Import offline root",
    description: "Button label for importing an offline root certificate.",
  },
  "caHierarchy.offline.commonName": {
    defaultMessage: "Common name",
    description: "CA common-name field label.",
  },
  "caHierarchy.offline.permittedDNSDomains": {
    defaultMessage: "Permitted DNS domains",
    description: "CA DNS name-constraint field label.",
  },
  "caHierarchy.offline.maxPathLen": {
    defaultMessage: "Max path length",
    description: "CA path-length constraint field label.",
  },
  "caHierarchy.offline.ttlDays": {
    defaultMessage: "TTL days",
    description: "CA lifetime field label.",
  },
  "caHierarchy.offline.rootCertPEM": {
    defaultMessage: "Offline root certificate PEM",
    description: "Field label for the imported public offline root certificate.",
  },
  "caHierarchy.offline.rootCeremonyID": {
    defaultMessage: "Root ceremony ID",
    description: "Field label for the offline root import ceremony id.",
  },
  "caHierarchy.offline.intermediate": {
    defaultMessage: "Intermediate",
    description: "Subheading for the offline intermediate panel.",
  },
  "caHierarchy.offline.startIntermediateCeremony": {
    defaultMessage: "Start intermediate ceremony",
    description: "Button label for opening an offline intermediate ceremony.",
  },
  "caHierarchy.offline.generateCSR": {
    defaultMessage: "Generate signer CSR",
    description: "Button label for creating a signer-held intermediate CSR.",
  },
  "caHierarchy.offline.importIntermediate": {
    defaultMessage: "Import offline-signed intermediate",
    description: "Button label for importing an offline-root-signed intermediate.",
  },
  "caHierarchy.offline.parentAuthorityID": {
    defaultMessage: "Offline-root authority ID",
    description: "Field label for the imported offline root authority id.",
  },
  "caHierarchy.offline.intermediateCeremonyID": {
    defaultMessage: "Intermediate ceremony ID",
    description: "Field label for the offline intermediate ceremony id.",
  },
  "caHierarchy.offline.signerCSRPEM": {
    defaultMessage: "Signer CSR PEM",
    description: "Field label for the generated intermediate CSR PEM.",
  },
  "caHierarchy.offline.signedIntermediatePEM": {
    defaultMessage: "Offline-signed intermediate PEM",
    description: "Field label for the signed intermediate certificate PEM.",
  },
  "caHierarchy.offline.signerHandle": {
    defaultMessage: "Signer handle",
    description: "Metadata label for a CA signer handle.",
  },
  "caHierarchy.offline.signerOffline": {
    defaultMessage: "offline",
    description: "Metadata value when an imported offline root has no signer handle.",
  },
  "caHierarchy.offline.placeholderCertificate": {
    defaultMessage: "-----BEGIN CERTIFICATE-----",
    description: "Placeholder for certificate PEM textareas.",
  },
  "caHierarchy.offline.placeholderCeremonyID": {
    defaultMessage: "ceremony-id",
    description: "Placeholder for ceremony id fields.",
  },
  "caHierarchy.offline.placeholderAuthorityID": {
    defaultMessage: "ca-authority-id",
    description: "Placeholder for CA authority id fields.",
  },
  "caHierarchy.offline.placeholderDNSDomain": {
    defaultMessage: "example.internal",
    description: "Placeholder DNS domain for CA name constraints.",
  },
  "caHierarchy.existing.heading": {
    defaultMessage: "Existing CA import",
    description: "Heading for the existing signer-backed CA import workflow.",
  },
  "caHierarchy.existing.description": {
    defaultMessage: "Bind an already-existing root or intermediate certificate chain to a signer-held key handle after m-of-n review.",
    description: "Short description for the existing signer-backed CA import workflow.",
  },
  "caHierarchy.existing.errorTitle": {
    defaultMessage: "Existing CA import failed",
    description: "Error title for failed existing CA import workflow actions.",
  },
  "caHierarchy.existing.formHeading": {
    defaultMessage: "Import signer-backed chain",
    description: "Subheading for the existing CA import form.",
  },
  "caHierarchy.existing.startCeremony": {
    defaultMessage: "Start existing-CA ceremony",
    description: "Button label for opening an existing CA import ceremony.",
  },
  "caHierarchy.existing.import": {
    defaultMessage: "Import existing CA",
    description: "Button label for importing an existing signer-backed CA chain.",
  },
  "caHierarchy.existing.chainPEM": {
    defaultMessage: "Existing CA chain PEM",
    description: "Field label for the imported public existing CA chain.",
  },
  "caHierarchy.existing.ceremonyID": {
    defaultMessage: "Existing CA ceremony ID",
    description: "Field label for the existing CA import ceremony id.",
  },
  "caHierarchy.existing.placeholderSignerHandle": {
    defaultMessage: "ca-hierarchy-imported-existing",
    description: "Placeholder signer handle for importing an existing CA chain.",
  },
  "caHierarchy.existing.placeholderCeremonyID": {
    defaultMessage: "ceremony id",
    description: "Placeholder for an existing CA import ceremony id field.",
  },
  "caHierarchy.existing.kind": {
    defaultMessage: "Kind",
    description: "Metadata label for an imported existing CA kind.",
  },
  "caHierarchy.existing.serial": {
    defaultMessage: "Serial",
    description: "Metadata label for an imported existing CA serial number.",
  },
  "nav.item.protocols": {
    defaultMessage: "Protocols",
    description: "Primary navigation item.",
  },
  "nav.item.acmeAndDns": {
    defaultMessage: "ACME and DNS",
    description: "Primary navigation item.",
  },
  "nav.item.enrollmentProtocols": {
    defaultMessage: "Enrollment protocols",
    description: "Primary navigation item.",
  },
  "nav.item.spiffe": {
    defaultMessage: "SPIFFE",
    description: "Primary navigation item.",
  },
  "nav.item.sshCa": {
    defaultMessage: "SSH CA",
    description: "Primary navigation item.",
  },
  "nav.item.sshTrust": {
    defaultMessage: "SSH trust",
    description: "Primary navigation item.",
  },
  "sshTrust.attested.description": {
    defaultMessage:
      "Short-lived SSH user certs require attestation evidence, an approver, principal constraints, TTL, source-address, and force-command policy. Self-approval blocked is a hard rule, not a UI hint.",
    description: "Description for the attestation-gated SSH user certificate form.",
  },
  "sshTrust.attested.approver": {
    defaultMessage: "Approver",
    description: "Field label for the distinct approver required for attested SSH user certificate issuance.",
  },
  "sshTrust.attested.boundPrincipals": {
    defaultMessage: "Bound principals",
    description: "Field label for requested SSH principals that must be bound to the attestation.",
  },
  "sshTrust.attested.sourceAddresses": {
    defaultMessage: "Source addresses",
    description: "Field label for OpenSSH source-address critical option values.",
  },
  "sshTrust.attested.forceCommand": {
    defaultMessage: "Force command",
    description: "Field label for the OpenSSH force-command critical option.",
  },
  "sshTrust.attested.resultConstraints": {
    defaultMessage: "approver {approver} | principals {principals} | source {source} | force {force}",
    description: "Summary of applied constraints returned with an issued attested SSH user certificate.",
  },
  "nav.item.codeSigning": {
    defaultMessage: "Code signing",
    description: "Primary navigation item.",
  },
  "nav.item.tsa": {
    defaultMessage: "TSA",
    description: "Primary navigation item.",
  },
  "nav.item.secrets": {
    defaultMessage: "Secrets",
    description: "Primary navigation item.",
  },
  "nav.item.nativeSecrets": {
    defaultMessage: "Native secrets",
    description: "Primary navigation item.",
  },
  "nav.item.pkiSecrets": {
    defaultMessage: "PKI secrets",
    description: "Primary navigation item.",
  },
  "nav.item.machineLogin": {
    defaultMessage: "Machine login",
    description: "Primary navigation item.",
  },
  "nav.item.secretSharing": {
    defaultMessage: "Secret sharing",
    description: "Primary navigation item.",
  },
  "nav.item.connectors": {
    defaultMessage: "Deployment connectors",
    description: "Primary navigation item.",
  },
  "nav.item.plugins": {
    defaultMessage: "Plugins",
    description: "Primary navigation item.",
  },
  "nav.item.risk": {
    defaultMessage: "Risk",
    description: "Primary navigation item.",
  },
  "nav.item.posture": {
    defaultMessage: "Crypto posture",
    description: "Primary navigation item.",
  },
  "nav.item.graph": {
    defaultMessage: "Credential graph",
    description: "Primary navigation item.",
  },
  "nav.item.assistant": {
    defaultMessage: "Assistant",
    description: "Primary navigation item.",
  },
  "assistant.mcp.writeToolsNeedControls": {
    defaultMessage: "Write-capable MCP tools require operation-specific controls",
    description: "Unavailable-state title when the Assistant receives MCP write tools but only has read-only form controls.",
  },
  "assistant.mcp.writeToolsSubjectFormDisabled": {
    defaultMessage: "The Assistant does not invoke them with the read-only subject form.",
    description: "Unavailable-state body explaining that write-capable MCP tools are not submitted through the subject-only form.",
  },
  "assistant.runtime.personalData": {
    defaultMessage: "Personal data",
    description: "Assistant runtime diagnostics label for personal-data egress posture.",
  },
  "assistant.runtime.statusLoading": {
    defaultMessage: "Runtime status is loading.",
    description: "Assistant runtime diagnostics loading detail.",
  },
  "assistant.runtime.piiEgress.redactLabel": {
    defaultMessage: "Redacted before model egress",
    description: "Assistant runtime diagnostics label for personal-data redaction mode.",
  },
  "assistant.runtime.piiEgress.redactDetail": {
    defaultMessage: "Personal data is removed before prompts leave the control plane.",
    description: "Assistant runtime diagnostics detail for personal-data redaction mode.",
  },
  "assistant.runtime.piiEgress.blockLabel": {
    defaultMessage: "Blocked on detection",
    description: "Assistant runtime diagnostics label for personal-data blocking mode.",
  },
  "assistant.runtime.piiEgress.blockDetail": {
    defaultMessage: "Prompts with personal data are refused before model egress.",
    description: "Assistant runtime diagnostics detail for personal-data blocking mode.",
  },
  "assistant.runtime.piiEgress.allowLabel": {
    defaultMessage: "Allowed by policy",
    description: "Assistant runtime diagnostics label for personal-data allow mode.",
  },
  "assistant.runtime.piiEgress.allowDetail": {
    defaultMessage: "Personal data may leave only under explicit operator policy.",
    description: "Assistant runtime diagnostics detail for personal-data allow mode.",
  },
  "assistant.runtime.piiEgress.unknownLabel": {
    defaultMessage: "Unknown",
    description: "Assistant runtime diagnostics label for an unrecognized personal-data egress mode.",
  },
  "assistant.runtime.piiEgress.unknownDetail": {
    defaultMessage: "Treat personal-data egress as unconfirmed until runtime status refreshes.",
    description: "Assistant runtime diagnostics detail for an unrecognized personal-data egress mode.",
  },
  "nav.item.incidents": {
    defaultMessage: "Incidents",
    description: "Primary navigation item.",
  },
  "nav.item.approvals": {
    defaultMessage: "Approvals",
    description: "Primary navigation item.",
  },
  "nav.item.audit": {
    defaultMessage: "Audit",
    description: "Primary navigation item.",
  },
  "nav.item.ownership": {
    defaultMessage: "Ownership",
    description: "Primary navigation item.",
  },
  "nav.item.rbac": {
    defaultMessage: "RBAC",
    description: "Primary navigation item.",
  },
  "nav.item.policy": {
    defaultMessage: "Policy",
    description: "Primary navigation item.",
  },
  "policy.overview.description": {
    defaultMessage:
      "Issue, deploy, and revoke mutations pass through the OPA/Rego default-deny gate, RA separation, dual-control approval, and bound-profile checks before state changes are emitted.",
    description: "Policy page overview text.",
  },
  "policy.enforcement.heading": {
    defaultMessage: "Enforcement path",
    description: "Heading for policy enforcement flow.",
  },
  "policy.enforcement.description": {
    defaultMessage:
      "The browser does not send a tenant id or bypass policy. It asks the lifecycle workflow to mutate state; the backend evaluates policy and either emits the event or returns a fail-closed problem.",
    description: "Description of policy enforcement flow.",
  },
  "policy.enforcement.auditPrefix": {
    defaultMessage:
      "Decisions are evidence events. Use Audit to inspect allow, deny, and evaluation-error records with the actor, resource, hash, and payload from the event stream. Action errors still appear where the operator started the workflow on",
    description: "Policy enforcement audit explanation before the identities link.",
  },
  "policy.enforcement.identitiesLink": {
    defaultMessage: "Identities",
    description: "Link text to the identities workflow from the policy page.",
  },
  "policy.enforcement.auditSuffix": {
    defaultMessage: ".",
    description: "Policy enforcement audit sentence suffix after the identities link.",
  },
  "policy.enforcement.policyDecisionsLink": {
    defaultMessage: "Open policy decisions in Audit",
    description: "Link text to policy decision audit events.",
  },
  "policy.enforcement.profileEvaluationsLink": {
    defaultMessage: "Open profile evaluations in Audit",
    description: "Link text to profile evaluation audit events.",
  },
  "policy.compliance.heading": {
    defaultMessage: "Compliance posture and reports",
    description: "Heading for compliance posture and reporting evidence.",
  },
  "policy.compliance.description": {
    defaultMessage:
      "Evidence packs are signed exports built from the audit log and cryptographic inventory. They show what trstctl can prove and what your organization must still attest; they are evidence, not certification.",
    description: "Description for compliance evidence packs.",
  },
  "policy.compliance.frameworkGroup": {
    defaultMessage: "Compliance framework",
    description: "Accessible label for the compliance framework selector.",
  },
  "policy.compliance.loadingEvidencePack": {
    defaultMessage: "Loading evidence pack.",
    description: "Loading state for compliance evidence packs.",
  },
  "policy.compliance.evidencePackUnavailable": {
    defaultMessage: "Evidence pack unavailable",
    description: "Error title when a compliance evidence pack cannot load.",
  },
  "policy.versions.heading": {
    defaultMessage: "Policy versions",
    description: "Heading for lifecycle policy versions.",
  },
  "policy.versions.description": {
    defaultMessage:
      "Active lifecycle policy versions are checked before activation, recorded as policy.version events, and enforced before lifecycle changes run.",
    description: "Description for lifecycle policy versions.",
  },
  "policy.versions.descriptionLabel": {
    defaultMessage: "Description",
    description: "Label and column header for a policy version description.",
  },
  "policy.versions.changeRef": {
    defaultMessage: "Change ref",
    description: "Label for the change reference on a policy version.",
  },
  "policy.versions.evidenceRefs": {
    defaultMessage: "Evidence refs",
    description: "Label for policy version evidence references.",
  },
  "policy.versions.lifecycleModule": {
    defaultMessage: "Lifecycle Rego module",
    description: "Label for the lifecycle policy Rego module editor.",
  },
  "policy.versions.authoring": {
    defaultMessage: "Authoring...",
    description: "Busy state while a policy version is being authored.",
  },
  "policy.versions.authorVersion": {
    defaultMessage: "Author version",
    description: "Button label to author a policy version.",
  },
  "policy.versions.activePolicy": {
    defaultMessage: "Active policy",
    description: "Heading for active policy version details.",
  },
  "policy.versions.status": {
    defaultMessage: "Status",
    description: "Policy version status label.",
  },
  "policy.versions.moduleHash": {
    defaultMessage: "Module hash",
    description: "Policy module digest label.",
  },
  "policy.versions.activated": {
    defaultMessage: "Activated",
    description: "Policy version activation timestamp label.",
  },
  "policy.versions.notActivated": {
    defaultMessage: "not activated",
    description: "Fallback value when a policy version has no activation timestamp.",
  },
  "policy.versions.noActive": {
    defaultMessage: "No live policy version is active.",
    description: "Empty state for active policy version details.",
  },
  "policy.versions.loading": {
    defaultMessage: "Loading policy versions.",
    description: "Loading state for policy versions.",
  },
  "policy.versions.unavailableTitle": {
    defaultMessage: "Policy versions unavailable",
    description: "Error title when policy versions cannot load.",
  },
  "policy.versions.tableLabel": {
    defaultMessage: "Policy versions",
    description: "Accessible label for the policy versions table.",
  },
  "policy.versions.hash": {
    defaultMessage: "Hash",
    description: "Column header for a policy version module hash.",
  },
  "policy.versions.change": {
    defaultMessage: "Change",
    description: "Column header for policy version change reference.",
  },
  "policy.versions.actions": {
    defaultMessage: "Actions",
    description: "Column header for policy version actions.",
  },
  "policy.versions.activating": {
    defaultMessage: "Activating...",
    description: "Busy state while a policy version is activating.",
  },
  "policy.versions.activate": {
    defaultMessage: "Activate",
    description: "Button label to activate a policy version.",
  },
  "policy.versions.rollingBack": {
    defaultMessage: "Rolling back...",
    description: "Busy state while a policy version is rolling back.",
  },
  "policy.versions.rollback": {
    defaultMessage: "Rollback",
    description: "Button label to roll back a policy version.",
  },
  "policy.versions.empty": {
    defaultMessage: "No policy versions.",
    description: "Empty state for the policy versions table.",
  },
  "policy.framework.pciDss": {
    defaultMessage: "PCI DSS",
    description: "Short label for the PCI DSS compliance evidence-pack selector.",
  },
  "policy.framework.hipaa": {
    defaultMessage: "HIPAA",
    description: "Short label for the HIPAA compliance evidence-pack selector.",
  },
  "policy.framework.soc2": {
    defaultMessage: "SOC 2",
    description: "Short label for the SOC 2 compliance evidence-pack selector.",
  },
  "policy.framework.nist80053": {
    defaultMessage: "NIST 800-53",
    description: "Short label for the NIST 800-53 compliance evidence-pack selector.",
  },
  "policy.framework.nistCsf20": {
    defaultMessage: "NIST CSF 2.0",
    description: "Short label for the NIST Cybersecurity Framework 2.0 evidence-pack selector.",
  },
  "policy.framework.fedramp": {
    defaultMessage: "FedRAMP",
    description: "Short label for the FedRAMP compliance evidence-pack selector.",
  },
  "policy.framework.cmmc20": {
    defaultMessage: "CMMC 2.0",
    description: "Short label for the CMMC 2.0 compliance evidence-pack selector.",
  },
  "policy.framework.cnsa20": {
    defaultMessage: "CNSA 2.0",
    description: "Short label for the CNSA 2.0 compliance evidence-pack selector.",
  },
  "policy.framework.cabfBR": {
    defaultMessage: "CA/B Forum BR",
    description: "Short label for the CA/Browser Forum Baseline Requirements compliance evidence-pack selector.",
  },
  "policy.framework.fips140": {
    defaultMessage: "FIPS 140",
    description: "Short label for the FIPS 140 compliance evidence-pack selector.",
  },
  "policy.framework.commonCriteria": {
    defaultMessage: "Common Criteria",
    description: "Short label for the Common Criteria compliance evidence-pack selector.",
  },
  "policy.framework.webtrust": {
    defaultMessage: "WebTrust",
    description: "Short label for the WebTrust compliance evidence-pack selector.",
  },
  "policy.framework.etsi": {
    defaultMessage: "ETSI",
    description: "Short label for the ETSI compliance evidence-pack selector.",
  },
  "policy.framework.eidas": {
    defaultMessage: "eIDAS",
    description: "Short label for the eIDAS compliance evidence-pack selector.",
  },
  "policy.framework.nis2": {
    defaultMessage: "NIS2",
    description: "Short label for the NIS2 compliance evidence-pack selector.",
  },
  "policy.reportType.inventorySnapshot": {
    defaultMessage: "Inventory snapshot",
    description: "Compliance report type option for an inventory snapshot.",
  },
  "policy.reportType.frameworkEvidencePack": {
    defaultMessage: "Framework evidence pack",
    description: "Compliance report type option for a signed framework evidence pack.",
  },
  "policy.reportType.cbomPosture": {
    defaultMessage: "CBOM posture",
    description: "Compliance report type option for cryptographic bill of materials posture.",
  },
  "policy.reportType.auditSummary": {
    defaultMessage: "Audit summary",
    description: "Compliance report type option for an audit-log summary.",
  },
  "policy.reportType.nhiComplianceMapping": {
    defaultMessage: "NHI compliance mapping",
    description: "Compliance report type option for non-human identity framework mappings.",
  },
  "policy.reporting.loading": {
    defaultMessage: "Loading report coverage.",
    description: "Loading state for compliance inventory reporting coverage.",
  },
  "policy.reporting.unavailableTitle": {
    defaultMessage: "Report coverage unavailable",
    description: "Error title when compliance inventory reporting cannot load.",
  },
  "policy.reporting.schedule": {
    defaultMessage: "Schedule",
    description: "Label for compliance report schedule name.",
  },
  "policy.reporting.framework": {
    defaultMessage: "Framework",
    description: "Label for compliance report framework.",
  },
  "policy.reporting.reportType": {
    defaultMessage: "Report type",
    description: "Label for compliance report type.",
  },
  "policy.reporting.cadenceDays": {
    defaultMessage: "Cadence days",
    description: "Label for compliance report schedule interval in days.",
  },
  "policy.reporting.recipientRef": {
    defaultMessage: "Recipient ref",
    description: "Label for a non-secret audit archive or recipient reference.",
  },
  "policy.reporting.scheduling": {
    defaultMessage: "Scheduling...",
    description: "Busy label while creating a compliance report schedule.",
  },
  "policy.reporting.createSchedule": {
    defaultMessage: "Create schedule",
    description: "Button label for creating a compliance report schedule.",
  },
  "policy.reporting.heading": {
    defaultMessage: "Compliance inventory report",
    description: "Heading for the compliance inventory reporting panel.",
  },
  "policy.reporting.generated": {
    defaultMessage: "{capability} generated {date}",
    description: "Generated timestamp line for the compliance inventory reporting panel.",
  },
  "policy.reporting.auditExport": {
    defaultMessage: "audit_export",
    description: "Technical delivery value for compliance report schedules.",
  },
  "policy.reporting.inventoryRows": {
    defaultMessage: "Inventory rows",
    description: "Compliance inventory report metric label.",
  },
  "policy.reporting.certificates": {
    defaultMessage: "Certificates",
    description: "Compliance inventory report metric label for certificates.",
  },
  "policy.reporting.cryptoAssets": {
    defaultMessage: "Crypto assets",
    description: "Compliance inventory report metric label for CBOM assets.",
  },
  "policy.reporting.discoverySchedules": {
    defaultMessage: "Discovery schedules",
    description: "Compliance inventory report metric label for discovery schedules.",
  },
  "policy.reporting.frameworks": {
    defaultMessage: "Frameworks",
    description: "Compliance inventory report metric label for supported frameworks.",
  },
  "policy.reporting.reportTypes": {
    defaultMessage: "Report types",
    description: "Compliance inventory report metric label for supported report types.",
  },
  "policy.reporting.schedules": {
    defaultMessage: "Schedules",
    description: "Compliance inventory report metric label for report schedules.",
  },
  "policy.reporting.enabledSchedules": {
    defaultMessage: "Enabled schedules",
    description: "Compliance inventory report metric label for enabled report schedules.",
  },
  "policy.reporting.reportTypeList": {
    defaultMessage: "Report types",
    description: "Compliance inventory report list title for report types.",
  },
  "policy.reporting.routeList": {
    defaultMessage: "API routes",
    description: "Compliance inventory report list title for API routes.",
  },
  "policy.reporting.tableCaption": {
    defaultMessage: "Compliance report schedules",
    description: "Accessible caption for compliance report schedules table.",
  },
  "policy.reporting.type": {
    defaultMessage: "Type",
    description: "Short compliance report schedule table heading for report type.",
  },
  "policy.reporting.cadence": {
    defaultMessage: "Cadence",
    description: "Short compliance report schedule table heading for interval.",
  },
  "policy.reporting.nextRun": {
    defaultMessage: "Next run",
    description: "Compliance report schedule table heading for next run time.",
  },
  "policy.reporting.empty": {
    defaultMessage: "No report schedules yet.",
    description: "Empty state for compliance report schedules.",
  },
  "policy.accessChange.heading": {
    defaultMessage: "Access-change approvals",
    description: "Heading for the NHI access-change approval panel.",
  },
  "policy.accessChange.description": {
    defaultMessage: "Requests bind NHI access changes to PR, ticket, or CAB evidence before a distinct reviewer approves or denies the change.",
    description: "Description for the NHI access-change approval panel.",
  },
  "policy.accessChange.action": {
    defaultMessage: "Action",
    description: "Label for the requested access-change action.",
  },
  "policy.accessChange.risk": {
    defaultMessage: "Risk",
    description: "Label for access-change request risk.",
  },
  "policy.accessChange.approvals": {
    defaultMessage: "Approvals",
    description: "Label for the approval quorum count.",
  },
  "policy.accessChange.changeRef": {
    defaultMessage: "Change ref",
    description: "Label for a PR, ticket, or CAB reference.",
  },
  "policy.accessChange.nhiId": {
    defaultMessage: "NHI id",
    description: "Label for the non-human identity identifier.",
  },
  "policy.accessChange.nhiKind": {
    defaultMessage: "NHI kind",
    description: "Label for the non-human identity kind.",
  },
  "policy.accessChange.displayName": {
    defaultMessage: "Display name",
    description: "Label for a human-readable NHI display name.",
  },
  "policy.accessChange.resource": {
    defaultMessage: "Resource",
    description: "Label for the governed resource.",
  },
  "policy.accessChange.entitlement": {
    defaultMessage: "Entitlement",
    description: "Label for the requested entitlement.",
  },
  "policy.accessChange.changeUrl": {
    defaultMessage: "Change URL",
    description: "Label for the change-management URL.",
  },
  "policy.accessChange.evidenceRefs": {
    defaultMessage: "Evidence refs",
    description: "Label for evidence references.",
  },
  "policy.accessChange.reason": {
    defaultMessage: "Reason",
    description: "Label for the request or decision reason.",
  },
  "policy.accessChange.opening": {
    defaultMessage: "Opening...",
    description: "Busy button text while opening an access-change request.",
  },
  "policy.accessChange.openRequest": {
    defaultMessage: "Open request",
    description: "Submit button for opening an access-change request.",
  },
  "policy.accessChange.loading": {
    defaultMessage: "Loading access-change requests.",
    description: "Loading state for access-change requests.",
  },
  "policy.accessChange.unavailableTitle": {
    defaultMessage: "Access-change requests unavailable",
    description: "Error title when access-change requests cannot load.",
  },
  "policy.accessChange.listLabel": {
    defaultMessage: "Access-change requests",
    description: "Accessible label for the access-change request list.",
  },
  "policy.accessChange.empty": {
    defaultMessage: "No access-change requests.",
    description: "Empty state for access-change requests.",
  },
  "policy.accessChange.changeSystem": {
    defaultMessage: "Change system",
    description: "Metric label for inferred change-management system.",
  },
  "policy.accessChange.status": {
    defaultMessage: "Status",
    description: "Metric label for access-change request status.",
  },
  "policy.accessChange.nhi": {
    defaultMessage: "NHI",
    description: "Metric label for non-human identity.",
  },
  "policy.accessChange.requestEvidence": {
    defaultMessage: "Request evidence",
    description: "List title for request evidence references.",
  },
  "policy.accessChange.changeReason": {
    defaultMessage: "Change reason",
    description: "Accessible label for the request reason panel.",
  },
  "policy.accessChange.decisionReason": {
    defaultMessage: "Decision reason",
    description: "Label for the access-change decision reason.",
  },
  "policy.accessChange.requiredForDenial": {
    defaultMessage: "Required for denial",
    description: "Placeholder for decision reason input.",
  },
  "policy.accessChange.approve": {
    defaultMessage: "Approve",
    description: "Button label to approve an access-change request.",
  },
  "policy.accessChange.deny": {
    defaultMessage: "Deny",
    description: "Button label to deny an access-change request.",
  },
  "policy.accessChange.terminal": {
    defaultMessage: "This request is terminal.",
    description: "Message shown when an access-change request can no longer be changed.",
  },
  "policy.accessChange.decisionsCaption": {
    defaultMessage: "Access-change decisions",
    description: "Accessible caption for access-change decisions table.",
  },
  "policy.accessChange.approver": {
    defaultMessage: "Approver",
    description: "Table heading for access-change decision approver.",
  },
  "policy.accessChange.decision": {
    defaultMessage: "Decision",
    description: "Table heading for access-change decision value.",
  },
  "policy.accessChange.evidence": {
    defaultMessage: "Evidence",
    description: "Table heading for decision evidence.",
  },
  "policy.accessChange.recorded": {
    defaultMessage: "Recorded",
    description: "Fallback text for a recorded decision without a reason.",
  },
  "policy.accessChange.noEvidenceRef": {
    defaultMessage: "No evidence ref",
    description: "Fallback text when a decision has no evidence reference.",
  },
  "policy.accessChange.openedNotice": {
    defaultMessage: "{name} {action} request opened from {changeRef}.",
    description: "Success notice after opening an access-change request.",
  },
  "policy.accessChange.decisionNotice": {
    defaultMessage: "{name} marked {decision}.",
    description: "Success notice after deciding an access-change request.",
  },
  "policy.dryRun.heading": {
    defaultMessage: "Policy authoring and dry run",
    description: "Heading for the tenant-scoped policy dry-run workbench.",
  },
  "policy.dryRun.description": {
    defaultMessage: "Candidate modules run against the authenticated tenant. Results include a decision, module digest, audit event, and bounded trace rows.",
    description: "Description for the tenant-scoped policy dry-run workbench.",
  },
  "policy.dryRun.formLabel": {
    defaultMessage: "Policy dry run",
    description: "Accessible label for the policy dry-run form.",
  },
  "policy.dryRun.kindLabel": {
    defaultMessage: "Policy kind",
    description: "Accessible label for lifecycle/ABAC policy kind selector.",
  },
  "policy.dryRun.lifecycle": {
    defaultMessage: "Lifecycle",
    description: "Policy dry-run kind selector label for lifecycle policy.",
  },
  "policy.dryRun.abac": {
    defaultMessage: "ABAC",
    description: "Policy dry-run kind selector label for ABAC deny overlays.",
  },
  "policy.dryRun.moduleLabel": {
    defaultMessage: "Candidate Rego module",
    description: "Textarea label for a candidate Rego module.",
  },
  "policy.dryRun.inputLabel": {
    defaultMessage: "Dry-run JSON input",
    description: "Textarea label for policy dry-run input JSON.",
  },
  "policy.dryRun.run": {
    defaultMessage: "Run dry run",
    description: "Submit button for a policy dry-run.",
  },
  "policy.dryRun.running": {
    defaultMessage: "Running...",
    description: "Busy submit button text while a policy dry-run is evaluating.",
  },
  "policy.dryRun.auditLink": {
    defaultMessage: "Open dry-run audit events",
    description: "Link label to policy dry-run audit events.",
  },
  "policy.dryRun.errorTitle": {
    defaultMessage: "Policy dry-run failed",
    description: "Error title for policy dry-run failures.",
  },
  "policy.dryRun.invalidInput": {
    defaultMessage: "dry-run input must be a JSON object",
    description: "Validation error when policy dry-run input is not a JSON object.",
  },
  "policy.dryRun.resultHeading": {
    defaultMessage: "Dry-run result",
    description: "Heading for policy dry-run result output.",
  },
  "policy.dryRun.decisionError": {
    defaultMessage: "Policy error",
    description: "Policy dry-run decision label for a compile or evaluation error.",
  },
  "policy.dryRun.decisionAllow": {
    defaultMessage: "Allow",
    description: "Policy dry-run decision label for an allow result.",
  },
  "policy.dryRun.decisionDeny": {
    defaultMessage: "Deny",
    description: "Policy dry-run decision label for a deny result.",
  },
  "policy.dryRun.decisionNone": {
    defaultMessage: "No decision",
    description: "Policy dry-run decision label when no decision is returned.",
  },
  "policy.dryRun.metricKind": {
    defaultMessage: "Kind",
    description: "Policy dry-run result metric label for policy kind.",
  },
  "policy.dryRun.metricValid": {
    defaultMessage: "Valid",
    description: "Policy dry-run result metric label for validation state.",
  },
  "policy.dryRun.validYes": {
    defaultMessage: "yes",
    description: "Short affirmative value in policy dry-run result metrics.",
  },
  "policy.dryRun.validNo": {
    defaultMessage: "no",
    description: "Short negative value in policy dry-run result metrics.",
  },
  "policy.dryRun.metricPackage": {
    defaultMessage: "Package",
    description: "Policy dry-run result metric label for Rego package.",
  },
  "policy.dryRun.metricQuery": {
    defaultMessage: "Query",
    description: "Policy dry-run result metric label for Rego query.",
  },
  "policy.dryRun.metricDigest": {
    defaultMessage: "Module digest",
    description: "Policy dry-run result metric label for module digest.",
  },
  "policy.dryRun.metricTenant": {
    defaultMessage: "Tenant",
    description: "Policy dry-run result metric label for tenant.",
  },
  "policy.dryRun.metricActor": {
    defaultMessage: "Actor",
    description: "Policy dry-run result metric label for actor.",
  },
  "policy.dryRun.metricIdempotency": {
    defaultMessage: "Idempotency",
    description: "Policy dry-run result metric label for idempotency key.",
  },
  "policy.dryRun.traceCaption": {
    defaultMessage: "Policy dry-run trace",
    description: "Accessible caption for policy dry-run trace table.",
  },
  "policy.dryRun.traceOp": {
    defaultMessage: "Op",
    description: "Policy dry-run trace table heading for operation.",
  },
  "policy.dryRun.traceLocation": {
    defaultMessage: "Location",
    description: "Policy dry-run trace table heading for source location.",
  },
  "policy.dryRun.traceNode": {
    defaultMessage: "Node",
    description: "Policy dry-run trace table heading for Rego node text.",
  },
  "policy.dryRun.traceMessage": {
    defaultMessage: "Message",
    description: "Policy dry-run trace table heading for trace message.",
  },
  "policy.nhiCompliance.heading": {
    defaultMessage: "NHI compliance mapping",
    description: "Heading for the NHI compliance mapping panel.",
  },
  "policy.nhiCompliance.generated": {
    defaultMessage: "{capability} generated {date} · {state}",
    description: "Generated timestamp line for the NHI compliance mapping panel.",
  },
  "policy.nhiCompliance.auditReady": {
    defaultMessage: "audit-ready",
    description: "Short state label when an NHI compliance report is audit-ready.",
  },
  "policy.nhiCompliance.draft": {
    defaultMessage: "draft",
    description: "Short state label when an NHI compliance report is not audit-ready.",
  },
  "policy.nhiCompliance.nhiRows": {
    defaultMessage: "NHI rows",
    description: "Metric label for total NHI rows in the compliance report.",
  },
  "policy.nhiCompliance.frameworks": {
    defaultMessage: "Frameworks",
    description: "Metric label for framework count in the NHI compliance report.",
  },
  "policy.nhiCompliance.mappedControls": {
    defaultMessage: "Mapped controls",
    description: "Metric label for mapped controls in the NHI compliance report.",
  },
  "policy.nhiCompliance.overprivileged": {
    defaultMessage: "Over-privileged",
    description: "Metric label for over-privileged NHI findings.",
  },
  "policy.nhiCompliance.staleFindings": {
    defaultMessage: "Stale findings",
    description: "Metric label for stale NHI findings.",
  },
  "policy.nhiCompliance.staticCredentials": {
    defaultMessage: "Static credentials",
    description: "Metric label for static NHI credential findings.",
  },
  "policy.nhiCompliance.evidenceRefs": {
    defaultMessage: "Evidence refs",
    description: "Metric label for evidence reference count.",
  },
  "policy.nhiCompliance.attestations": {
    defaultMessage: "Attestations",
    description: "Metric label for operator attestation count.",
  },
  "policy.nhiCompliance.frameworkList": {
    defaultMessage: "Frameworks",
    description: "List title for NHI compliance frameworks.",
  },
  "policy.nhiCompliance.evidenceRoutes": {
    defaultMessage: "Evidence routes",
    description: "List title for NHI compliance evidence routes.",
  },
  "policy.nhiCompliance.tableCaption": {
    defaultMessage: "NHI compliance control mappings",
    description: "Accessible caption for the NHI compliance control mapping table.",
  },
  "policy.nhiCompliance.frameworkColumn": {
    defaultMessage: "Framework",
    description: "Table heading for framework in the NHI compliance mapping table.",
  },
  "policy.nhiCompliance.controlColumn": {
    defaultMessage: "Control",
    description: "Table heading for control in the NHI compliance mapping table.",
  },
  "policy.nhiCompliance.statusColumn": {
    defaultMessage: "Status",
    description: "Table heading for status in the NHI compliance mapping table.",
  },
  "policy.nhiCompliance.evidenceColumn": {
    defaultMessage: "Evidence",
    description: "Table heading for evidence in the NHI compliance mapping table.",
  },
  "policy.nhiCompliance.mappedSignals": {
    defaultMessage: "{count} mapped signals",
    description: "Per-control mapped posture signal count in the NHI compliance table.",
  },
  "policy.nhiCompliance.residualAttestations": {
    defaultMessage: "Residual attestations",
    description: "List title for NHI compliance residual attestations.",
  },
  "nav.item.privacy": {
    defaultMessage: "Privacy",
    description: "Primary navigation item.",
  },
  "nav.item.integrate": {
    defaultMessage: "Integration & SDKs",
    description: "Primary navigation item.",
  },
  "nav.item.apiExplorer": {
    defaultMessage: "API explorer",
    description: "Contextual navigation item for the runnable API explorer.",
  },
  "nav.item.operations": {
    defaultMessage: "Operations",
    description: "Primary navigation item.",
  },
  "nav.item.notifications": {
    defaultMessage: "Notifications",
    description: "Primary navigation item.",
  },
  "nav.item.platform": {
    defaultMessage: "Platform",
    description: "Primary navigation item.",
  },
  "nav.item.sso": {
    defaultMessage: "SSO",
    description: "Primary navigation item.",
  },
  "nav.item.apiDistribution": {
    defaultMessage: "API and distribution",
    description: "Primary navigation item.",
  },
  "command.title": {
    defaultMessage: "Command palette",
    description: "Command palette dialog title.",
  },
  "command.description": {
    defaultMessage: "Jump to routes or search certificate, identity, and secret metadata.",
    description: "Command palette dialog description.",
  },
  "command.close": {
    defaultMessage: "Close command palette",
    description: "Command palette close button label.",
  },
  "command.searchLabel": {
    defaultMessage: "Search routes and inventory",
    description: "Command palette search field accessible label.",
  },
  "command.searchPlaceholder": {
    defaultMessage: "Search routes, certificates, identities, or secrets",
    description: "Command palette search field placeholder.",
  },
  "command.sourcesUnavailable": {
    defaultMessage: "Some inventory sources are temporarily unavailable.",
    description: "Command palette unavailable source warning.",
  },
  "command.searchingInventory": {
    defaultMessage: "Searching inventory...",
    description: "Command palette loading status.",
  },
  "command.routes": {
    defaultMessage: "Routes",
    description: "Command palette route section title.",
  },
  "command.inventory": {
    defaultMessage: "Inventory",
    description: "Command palette inventory section title.",
  },
  "command.noResults": {
    defaultMessage: "No routes or inventory matched.",
    description: "Command palette empty state.",
  },
  "command.routeDescription": {
    defaultMessage: "Route · {group}",
    description: "Command palette description for a route command.",
  },
  "command.enter": {
    defaultMessage: "Enter",
    description: "Keyboard activation hint.",
  },
  "search.kind.certificate": {
    defaultMessage: "Certificate",
    description: "Global search result kind label.",
  },
  "search.kind.identity": {
    defaultMessage: "Identity",
    description: "Global search result kind label.",
  },
  "search.kind.secret": {
    defaultMessage: "Secret",
    description: "Global search result kind label.",
  },
  "agents.endpointDiscovery.heading": {
    defaultMessage: "Endpoint discovery",
    description: "Heading for the served endpoint discovery capability panel on an agent detail view.",
  },
  "agents.endpointDiscovery.description": {
    defaultMessage: "Inventory batches arrive through {path} and project into Discovery findings.",
    description: "Explanation of the served agent inventory report path.",
  },
  "agents.endpointDiscovery.reportPath": {
    defaultMessage: "Report path",
    description: "Label for the agent inventory report path field.",
  },
  "agents.endpointDiscovery.metadataOnly": {
    defaultMessage: "metadata-only",
    description: "Badge indicating agent discovery reports metadata without secret payloads.",
  },
  "agents.endpointDiscovery.payload": {
    defaultMessage: "payload",
    description: "Badge for a non-metadata-only discovery capability.",
  },
  "agents.endpointDiscovery.noKeyBytes": {
    defaultMessage: "no key bytes",
    description: "Badge indicating private key bytes are not transported.",
  },
  "agents.endpointDiscovery.filesystem": {
    defaultMessage: "Filesystem certificates",
    description: "Fallback label for filesystem endpoint discovery capability.",
  },
  "agents.endpointDiscovery.pkcs11": {
    defaultMessage: "PKCS#11 token certificates",
    description: "Fallback label for PKCS#11 endpoint discovery capability.",
  },
  "agents.endpointDiscovery.windowsStore": {
    defaultMessage: "Windows certificate store",
    description: "Fallback label for Windows certificate store endpoint discovery capability.",
  },
  "agents.endpointDiscovery.k8sSecret": {
    defaultMessage: "Kubernetes TLS Secrets",
    description: "Fallback label for Kubernetes Secret endpoint discovery capability.",
  },
  "agents.endpointDiscovery.trustStore": {
    defaultMessage: "Trust stores",
    description: "Fallback label for trust-store endpoint discovery capability.",
  },
  "agents.endpointDiscovery.privateKey": {
    defaultMessage: "Private-key material",
    description: "Fallback label for private-key endpoint discovery capability.",
  },
  "nhi.inventory.title": {
    defaultMessage: "Non-human identity inventory",
    description: "Dashboard section title for the unified non-human identity inventory.",
  },
  "nhi.inventory.description": {
    defaultMessage: "every machine identity by type, with a shared risk lens",
    description: "Dashboard section description for the unified non-human identity inventory.",
  },
  "nhi.inventory.total": {
    defaultMessage: "Total identities",
    description: "Dashboard stat label for total non-human identities.",
  },
  "nhi.inventory.highRisk": {
    defaultMessage: "High risk",
    description: "Dashboard stat label for high-risk non-human identities.",
  },
  "risk.nhiPolicy.heading": {
    defaultMessage: "NHI policy compliance",
    description: "Risk page section heading for NHI policy compliance posture.",
  },
  "risk.nhiPolicy.summary": {
    defaultMessage:
      "CAP-GOV-03: {violations} policy violations across {total} governed NHIs; {rotation} rotation, {scope} scope, {geo} geography, {expiry} expiry, {purpose} purpose gaps.",
    description: "Risk page summary for NHI policy compliance posture.",
  },
  "risk.nhiPolicy.loading": {
    defaultMessage: "Loading NHI policy compliance.",
    description: "Loading text for NHI policy compliance posture.",
  },
  "risk.nhiPolicy.unavailableTitle": {
    defaultMessage: "NHI policy compliance unavailable",
    description: "Error title when NHI policy compliance cannot be loaded.",
  },
  "risk.nhiPolicy.empty": {
    defaultMessage: "No NHI policy violations detected.",
    description: "Empty-state text for NHI policy compliance posture.",
  },
  "risk.nhiPolicy.caption": {
    defaultMessage: "NHI policy compliance violations",
    description: "Accessible caption for the NHI policy compliance table.",
  },
  "risk.nhiPolicy.nhi": {
    defaultMessage: "NHI",
    description: "NHI policy compliance table column for the identity.",
  },
  "risk.nhiPolicy.violations": {
    defaultMessage: "Violations",
    description: "NHI policy compliance table column for violation types.",
  },
  "risk.nhiPolicy.envelope": {
    defaultMessage: "Allowed envelope",
    description: "NHI policy compliance table column for disallowed scopes and geographies.",
  },
  "risk.nhiPolicy.envelopeValue": {
    defaultMessage: "Scopes: {scopes} / Geos: {geos}",
    description: "NHI policy compliance table value for disallowed scopes and geographies.",
  },
  "risk.nhiPolicy.none": {
    defaultMessage: "none",
    description: "Fallback text when no disallowed NHI policy value exists.",
  },
  "risk.nhiPolicy.recommendation": {
    defaultMessage: "Recommendation",
    description: "NHI policy compliance table column for remediation recommendation.",
  },
  "risk.nhiOverprivilege.heading": {
    defaultMessage: "NHI over-privilege",
    description: "Risk page section heading for NHI over-privilege posture.",
  },
  "risk.nhiOverprivilege.summary": {
    defaultMessage: "CAP-POST-01: {overprivileged} over-privileged of {total} usage-backed NHIs; {unused} unused grants.",
    description: "Risk page summary for NHI over-privilege posture.",
  },
  "risk.nhiOverprivilege.loading": {
    defaultMessage: "Loading NHI posture.",
    description: "Loading text for NHI over-privilege posture.",
  },
  "risk.nhiOverprivilege.unavailableTitle": {
    defaultMessage: "NHI posture unavailable",
    description: "Error title when NHI over-privilege posture cannot be loaded.",
  },
  "risk.nhiOverprivilege.empty": {
    defaultMessage: "No usage-backed excessive scope detected.",
    description: "Empty-state text for NHI over-privilege posture.",
  },
  "risk.nhiOverprivilege.caption": {
    defaultMessage: "NHI over-privilege recommendations",
    description: "Accessible caption for the NHI over-privilege recommendations table.",
  },
  "risk.nhiOverprivilege.nhi": {
    defaultMessage: "NHI",
    description: "NHI over-privilege table column for the identity.",
  },
  "risk.nhiOverprivilege.severity": {
    defaultMessage: "Severity",
    description: "NHI over-privilege table column for severity.",
  },
  "risk.nhiOverprivilege.unusedGrants": {
    defaultMessage: "Unused grants",
    description: "NHI over-privilege table column for unused grants.",
  },
  "risk.nhiOverprivilege.recommendation": {
    defaultMessage: "Least-privilege recommendation",
    description: "NHI over-privilege table column for the right-sizing recommendation.",
  },
  "risk.nhiStale.heading": {
    defaultMessage: "Stale and dormant NHIs",
    description: "Risk page section heading for stale, unused, orphaned, and dormant NHI posture.",
  },
  "risk.nhiStale.summary": {
    defaultMessage: "CAP-POST-02: {findings} stale, unused, orphaned, or dormant of {total} analyzed NHIs; {dormant} dormant, {orphaned} orphaned.",
    description: "Risk page summary for stale, unused, orphaned, and dormant NHI posture.",
  },
  "risk.nhiStale.loading": {
    defaultMessage: "Loading stale NHI posture.",
    description: "Loading text for stale NHI posture.",
  },
  "risk.nhiStale.unavailableTitle": {
    defaultMessage: "Stale NHI posture unavailable",
    description: "Error title when stale NHI posture cannot be loaded.",
  },
  "risk.nhiStale.empty": {
    defaultMessage: "No stale, unused, orphaned, or dormant NHI evidence detected.",
    description: "Empty-state text for stale NHI posture.",
  },
  "risk.nhiStale.caption": {
    defaultMessage: "Stale and dormant NHI recommendations",
    description: "Accessible caption for the stale NHI recommendations table.",
  },
  "risk.nhiStale.nhi": {
    defaultMessage: "NHI",
    description: "Stale NHI table column for the identity.",
  },
  "risk.nhiStale.finding": {
    defaultMessage: "Finding",
    description: "Stale NHI table column for finding type and severity.",
  },
  "risk.nhiStale.age": {
    defaultMessage: "Age",
    description: "Stale NHI table column for activity and creation age.",
  },
  "risk.nhiStale.ageValue": {
    defaultMessage: "{activity}d activity / {created}d created",
    description: "Stale NHI table age value.",
  },
  "risk.nhiStale.recommendation": {
    defaultMessage: "Recommendation",
    description: "Stale NHI table column for remediation recommendation.",
  },
  "risk.contextual.heading": {
    defaultMessage: "Contextual priorities",
    description: "Risk page section heading for blast-radius contextual prioritization.",
  },
  "risk.contextual.summary": {
    defaultMessage: "CAP-POST-05: {priorities} prioritized of {total} credentials; {highBlast} high-blast-radius, {weakCrypto} with weak crypto context.",
    description: "Risk page summary for contextual risk priorities.",
  },
  "risk.contextual.loading": {
    defaultMessage: "Loading contextual priorities.",
    description: "Loading text for contextual risk priorities.",
  },
  "risk.contextual.unavailableTitle": {
    defaultMessage: "Contextual priorities unavailable",
    description: "Error title when contextual risk priorities cannot be loaded.",
  },
  "risk.contextual.empty": {
    defaultMessage: "No contextual risk priorities detected.",
    description: "Empty-state text for contextual risk priorities.",
  },
  "risk.contextual.caption": {
    defaultMessage: "Blast-radius contextual risk priorities",
    description: "Accessible caption for the contextual risk table.",
  },
  "risk.contextual.credential": {
    defaultMessage: "Credential",
    description: "Contextual risk table column for the credential.",
  },
  "risk.contextual.priority": {
    defaultMessage: "Priority",
    description: "Contextual risk table column for priority score and reasons.",
  },
  "risk.contextual.blastRadius": {
    defaultMessage: "Blast radius",
    description: "Contextual risk table column for graph blast-radius counts.",
  },
  "risk.contextual.action": {
    defaultMessage: "Action",
    description: "Contextual risk table column for recommended action.",
  },
  "risk.contextual.scoreValue": {
    defaultMessage: "{contextual} contextual / {base} base",
    description: "Contextual risk score comparison value.",
  },
  "risk.contextual.blastValue": {
    defaultMessage: "{total} affected; {resources} resources, {cryptoAssets} crypto assets",
    description: "Contextual risk blast-radius count value.",
  },
  "risk.nhiStatic.heading": {
    defaultMessage: "Static credentials",
    description: "Risk page section heading for long-lived and static NHI credentials.",
  },
  "risk.nhiStatic.summary": {
    defaultMessage: "CAP-POST-03: {findings} static or long-lived of {total} analyzed NHIs; {longLived} long-lived, {staticCredentials} static.",
    description: "Risk page summary for static credential posture.",
  },
  "risk.nhiStatic.loading": {
    defaultMessage: "Loading static credential posture.",
    description: "Loading text for static credential posture.",
  },
  "risk.nhiStatic.unavailableTitle": {
    defaultMessage: "Static credential posture unavailable",
    description: "Error title when static credential posture cannot be loaded.",
  },
  "risk.nhiStatic.empty": {
    defaultMessage: "No long-lived or static credential evidence detected.",
    description: "Empty-state text for static credential posture.",
  },
  "risk.nhiStatic.caption": {
    defaultMessage: "Static credential recommendations",
    description: "Accessible caption for the static credential recommendations table.",
  },
  "risk.nhiStatic.nhi": {
    defaultMessage: "NHI",
    description: "Static credential table column for the identity.",
  },
  "risk.nhiStatic.finding": {
    defaultMessage: "Finding",
    description: "Static credential table column for finding type and severity.",
  },
  "risk.nhiStatic.lifetime": {
    defaultMessage: "Lifetime",
    description: "Static credential table column for credential lifetime and rotation age.",
  },
  "risk.nhiStatic.lifetimeValue": {
    defaultMessage: "{age}d old / {ttl}d TTL / {rotation}d rotation",
    description: "Static credential table lifetime value.",
  },
  "risk.nhiStatic.recommendation": {
    defaultMessage: "Recommendation",
    description: "Static credential table column for remediation recommendation.",
  },
  "risk.nhiExposure.heading": {
    defaultMessage: "Exposed NHI deployments",
    description: "Risk page section heading for internet-exposed and insecurely deployed NHI posture.",
  },
  "risk.nhiExposure.summary": {
    defaultMessage:
      "CAP-POST-04: {findings} exposure findings across {total} analyzed NHIs; {exposed} internet-exposed, {weakAuth} weak auth, {insecureTransport} insecure transport.",
    description: "Risk page summary for internet-exposed and insecurely deployed NHI posture.",
  },
  "risk.nhiExposure.loading": {
    defaultMessage: "Loading exposed NHI posture.",
    description: "Loading text for exposed NHI posture.",
  },
  "risk.nhiExposure.unavailableTitle": {
    defaultMessage: "Exposed NHI posture unavailable",
    description: "Error title when exposed NHI posture cannot be loaded.",
  },
  "risk.nhiExposure.empty": {
    defaultMessage: "No internet-exposed or insecure-deployment NHI evidence detected.",
    description: "Empty-state text for exposed NHI posture.",
  },
  "risk.nhiExposure.caption": {
    defaultMessage: "Exposed NHI deployment recommendations",
    description: "Accessible caption for the exposed NHI posture table.",
  },
  "risk.nhiExposure.nhi": {
    defaultMessage: "NHI",
    description: "Exposed NHI table column for the identity.",
  },
  "risk.nhiExposure.finding": {
    defaultMessage: "Finding",
    description: "Exposed NHI table column for finding type and severity.",
  },
  "risk.nhiExposure.exposure": {
    defaultMessage: "Exposure",
    description: "Exposed NHI table column for exposure details.",
  },
  "risk.nhiExposure.exposureValue": {
    defaultMessage: "{level} / {auth} / {transport}",
    description: "Exposed NHI table value for exposure level, auth mode, and transport security.",
  },
  "risk.nhiExposure.unknown": {
    defaultMessage: "unknown",
    description: "Fallback text when exposed NHI posture lacks one exposure detail.",
  },
  "risk.nhiExposure.recommendation": {
    defaultMessage: "Recommendation",
    description: "Exposed NHI table column for remediation recommendation.",
  },
  "identities.decommission.ariaLabel": {
    defaultMessage: "NHI decommission",
    description: "Accessible label for the NHI decommission form on the identities page.",
  },
  "identities.decommission.signal": {
    defaultMessage: "Signal",
    description: "Label for the decommission signal selector.",
  },
  "identities.decommission.subject": {
    defaultMessage: "Subject",
    description: "Label for the owner subject field in the NHI decommission form.",
  },
  "identities.decommission.vendor": {
    defaultMessage: "Vendor",
    description: "Label for the vendor field in the NHI decommission form.",
  },
  "identities.decommission.inactiveBefore": {
    defaultMessage: "Inactive before",
    description: "Label for the inactivity cutoff field in the NHI decommission form.",
  },
  "identities.decommission.departure": {
    defaultMessage: "Departure",
    description: "Option label for an owner-departure decommission signal.",
  },
  "identities.decommission.vendorTerm": {
    defaultMessage: "Vendor term",
    description: "Option label for a vendor-termination decommission signal.",
  },
  "identities.decommission.inactivity": {
    defaultMessage: "Inactivity",
    description: "Option label for an inactivity decommission signal.",
  },
  "identities.decommission.submit": {
    defaultMessage: "Decommission",
    description: "Submit button for the NHI decommission form.",
  },
  "identities.decommission.reasonPlaceholder": {
    defaultMessage: "CAB-1234",
    description: "Placeholder for a decommission change-management reason.",
  },
  "owners.attribution.heading": {
    defaultMessage: "Ownership attribution",
    description: "Owners page section heading for NHI ownership attribution.",
  },
  "owners.attribution.loading": {
    defaultMessage: "Loading ownership attribution...",
    description: "Loading text while NHI ownership attribution is fetched.",
  },
  "owners.attribution.error": {
    defaultMessage: "Could not load ownership attribution",
    description: "Error title when NHI ownership attribution cannot be fetched.",
  },
  "owners.attribution.ariaLabel": {
    defaultMessage: "NHI ownership attribution",
    description: "Accessible label for the NHI ownership attribution table.",
  },
  "owners.attribution.emptyTitle": {
    defaultMessage: "No attribution rows",
    description: "Empty-state title for NHI ownership attribution.",
  },
  "owners.attribution.emptyMessage": {
    defaultMessage: "No managed or discovered NHIs are available for attribution.",
    description: "Empty-state message for NHI ownership attribution.",
  },
  "owners.attribution.nhi": {
    defaultMessage: "NHI",
    description: "Column header for the attributed non-human identity.",
  },
  "owners.attribution.kind": {
    defaultMessage: "Kind",
    description: "Column header for the attributed NHI kind.",
  },
  "owners.attribution.owner": {
    defaultMessage: "Owner",
    description: "Column header for the attributed owner.",
  },
  "owners.attribution.ownerKind": {
    defaultMessage: "Owner kind",
    description: "Column header for the attributed owner kind.",
  },
  "owners.attribution.source": {
    defaultMessage: "Source",
    description: "Column header for the attribution source.",
  },
  "owners.attribution.unattributed": {
    defaultMessage: "Unattributed",
    description: "Fallback owner label for an unattributed NHI.",
  },
  "owners.attribution.orphaned": {
    defaultMessage: "orphaned",
    description: "Fallback owner-kind label for an unattributed NHI.",
  },
  "notifications.channels.heading": {
    defaultMessage: "Channel coverage",
    description: "Heading for the configured notification channel catalog.",
  },
  "notifications.channels.configuredCount": {
    defaultMessage: "{count} configured",
    description: "Count of configured notification channel families.",
  },
  "notifications.channels.unavailableTitle": {
    defaultMessage: "Notification channels unavailable",
    description: "Error title when notification channel status cannot be fetched.",
  },
  "notifications.channels.loadError": {
    defaultMessage: "Could not load notification channels",
    description: "Fallback error when notification channel status cannot be fetched.",
  },
  "notifications.channels.configured": {
    defaultMessage: "configured",
    description: "Status badge for a configured notification channel.",
  },
  "notifications.channels.unconfigured": {
    defaultMessage: "unconfigured",
    description: "Status badge for a notification channel family that is supported but not configured.",
  },
  "notifications.channels.authoringHeading": {
    defaultMessage: "Channel authoring",
    description: "Heading for tenant notification channel authoring controls.",
  },
  "notifications.channels.type": {
    defaultMessage: "Channel type",
    description: "Label for selecting a notification channel type.",
  },
  "notifications.channels.label": {
    defaultMessage: "Display label",
    description: "Label for notification channel display name.",
  },
  "notifications.channels.endpointUrl": {
    defaultMessage: "Endpoint URL",
    description: "Label for notification channel endpoint URL.",
  },
  "notifications.channels.credentialRef": {
    defaultMessage: "Channel credential reference",
    description: "Label for notification channel credential reference.",
  },
  "notifications.channels.enabled": {
    defaultMessage: "enabled",
    description: "Enabled status label for a notification channel.",
  },
  "notifications.channels.disabled": {
    defaultMessage: "disabled",
    description: "Disabled status label for a notification channel.",
  },
  "notifications.channels.save": {
    defaultMessage: "Save channel",
    description: "Button label for saving a notification channel.",
  },
  "notifications.channels.saving": {
    defaultMessage: "Saving...",
    description: "Busy button label while saving a notification channel.",
  },
  "notifications.channels.saved": {
    defaultMessage: "Channel saved",
    description: "Toast title after saving a notification channel.",
  },
  "notifications.channels.saveError": {
    defaultMessage: "Could not save notification channel",
    description: "Fallback error when notification channel creation fails.",
  },
  "notifications.routing.heading": {
    defaultMessage: "Routing policies",
    description: "Heading for notification routing policy authoring.",
  },
  "notifications.routing.description": {
    defaultMessage: "Map severity tiers to configured channels, assign an owner, and preview the digest cadence.",
    description: "Description for notification routing policy authoring.",
  },
  "notifications.routing.loadError": {
    defaultMessage: "Could not load notification routing policies",
    description: "Fallback error when notification routing policies cannot be fetched.",
  },
  "notifications.routing.createError": {
    defaultMessage: "Could not create notification routing policy",
    description: "Fallback error when notification routing policy creation fails.",
  },
  "notifications.routing.testError": {
    defaultMessage: "Could not queue notification channel test",
    description: "Fallback error when notification channel test queueing fails.",
  },
  "notifications.routing.policyCreated": {
    defaultMessage: "Routing policy saved",
    description: "Toast title after saving a notification routing policy.",
  },
  "notifications.routing.testQueued": {
    defaultMessage: "Channel test queued",
    description: "Toast title after queueing a notification channel test.",
  },
  "notifications.routing.name": {
    defaultMessage: "Policy name",
    description: "Label for notification routing policy name.",
  },
  "notifications.routing.ownerRef": {
    defaultMessage: "Owner reference",
    description: "Label for notification routing policy owner reference.",
  },
  "notifications.routing.ownerEmail": {
    defaultMessage: "Owner email",
    description: "Label for notification routing policy owner email.",
  },
  "notifications.routing.digestInterval": {
    defaultMessage: "Digest interval",
    description: "Label for notification routing policy digest interval.",
  },
  "notifications.routing.intervalOneHour": {
    defaultMessage: "1 hour",
    description: "Notification routing digest interval option for one hour.",
  },
  "notifications.routing.intervalTwelveHours": {
    defaultMessage: "12 hours",
    description: "Notification routing digest interval option for twelve hours.",
  },
  "notifications.routing.intervalOneDay": {
    defaultMessage: "24 hours",
    description: "Notification routing digest interval option for one day.",
  },
  "notifications.routing.intervalSevenDays": {
    defaultMessage: "7 days",
    description: "Notification routing digest interval option for seven days.",
  },
  "notifications.routing.defaultChannels": {
    defaultMessage: "Default channels",
    description: "Label for notification routing default channels.",
  },
  "notifications.routing.criticalChannels": {
    defaultMessage: "Critical channels",
    description: "Label for critical severity notification channels.",
  },
  "notifications.routing.warningChannels": {
    defaultMessage: "Warning channels",
    description: "Label for warning severity notification channels.",
  },
  "notifications.routing.lowChannels": {
    defaultMessage: "Low channels",
    description: "Label for low severity notification channels.",
  },
  "notifications.routing.save": {
    defaultMessage: "Save policy",
    description: "Submit button for notification routing policy form.",
  },
  "notifications.routing.saving": {
    defaultMessage: "Saving...",
    description: "Busy state for notification routing policy form.",
  },
  "notifications.routing.testHeading": {
    defaultMessage: "Test delivery",
    description: "Heading for notification channel test form.",
  },
  "notifications.routing.channel": {
    defaultMessage: "Channel",
    description: "Label for notification channel selection.",
  },
  "notifications.routing.severity": {
    defaultMessage: "Severity",
    description: "Label for notification test severity.",
  },
  "notifications.routing.testSubject": {
    defaultMessage: "Test subject",
    description: "Label for notification test subject.",
  },
  "notifications.routing.credentialRef": {
    defaultMessage: "Credential reference",
    description: "Label for redacted notification test credential reference.",
  },
  "notifications.routing.sendTest": {
    defaultMessage: "Queue test",
    description: "Submit button for notification channel test form.",
  },
  "notifications.routing.testing": {
    defaultMessage: "Queueing...",
    description: "Busy state for notification channel test form.",
  },
  "notifications.routing.noPolicies": {
    defaultMessage: "No routing policies yet.",
    description: "Empty state for notification routing policy list.",
  },
  "notifications.routing.owner": {
    defaultMessage: "Owner",
    description: "Label for notification routing policy owner summary.",
  },
  "notifications.routing.nextDigest": {
    defaultMessage: "Next digest",
    description: "Label for notification routing digest preview summary.",
  },
  "notifications.error.unavailable": {
    defaultMessage: "Notifications unavailable",
    description: "Error title when the notification inbox cannot be fetched.",
  },
  "notifications.error.loadFailed": {
    defaultMessage: "Could not load notifications",
    description: "Fallback error when the notification inbox cannot be fetched.",
  },
  "notifications.action.markedRead": {
    defaultMessage: "Notification marked read",
    description: "Toast title after marking a notification read.",
  },
  "notifications.action.markReadFailed": {
    defaultMessage: "Mark read failed",
    description: "Toast and error title when marking a notification read fails.",
  },
  "notifications.action.markReadLoadFailed": {
    defaultMessage: "Could not mark notification read",
    description: "Fallback error when marking a notification read fails.",
  },
  "notifications.action.requeued": {
    defaultMessage: "Notification requeued",
    description: "Toast title after requeueing a dead-letter notification.",
  },
  "notifications.action.requeueFailed": {
    defaultMessage: "Requeue failed",
    description: "Toast and error title when requeueing a notification fails.",
  },
  "notifications.action.requeueLoadFailed": {
    defaultMessage: "Could not requeue notification",
    description: "Fallback error when requeueing a notification fails.",
  },
  "notifications.queue.tablist": {
    defaultMessage: "Notification queues",
    description: "Accessible label for notification queue tabs.",
  },
  "notifications.queue.all": {
    defaultMessage: "All",
    description: "Tab label for all notifications.",
  },
  "notifications.queue.deadLetter": {
    defaultMessage: "Dead-letter",
    description: "Tab label for dead-letter notifications.",
  },
  "notifications.filter.type": {
    defaultMessage: "Type filter",
    description: "Label for notification type filter.",
  },
  "notifications.filter.typeAll": {
    defaultMessage: "All types",
    description: "Option label showing all notification types.",
  },
  "notifications.filter.status": {
    defaultMessage: "Status filter",
    description: "Label for notification status filter.",
  },
  "notifications.filter.statusAll": {
    defaultMessage: "All statuses",
    description: "Option label showing all notification statuses.",
  },
  "notifications.status.pending": {
    defaultMessage: "pending",
    description: "Notification status option.",
  },
  "notifications.status.sent": {
    defaultMessage: "sent",
    description: "Notification status option.",
  },
  "notifications.status.read": {
    defaultMessage: "read",
    description: "Notification status option.",
  },
  "notifications.status.dead": {
    defaultMessage: "dead",
    description: "Notification status option.",
  },
  "notifications.count.total": {
    defaultMessage: "{count} notifications",
    description: "Notification result count summary.",
  },
  "notifications.count.unread": {
    defaultMessage: "{count} unread",
    description: "Unread notification count summary.",
  },
  "notifications.loading": {
    defaultMessage: "Loading notifications...",
    description: "Loading state for notification inbox rows.",
  },
  "notifications.emptyTitle": {
    defaultMessage: "No notifications found",
    description: "Empty state title for notification inbox rows.",
  },
  "notifications.emptyBody": {
    defaultMessage: "Adjust filters or refresh the inbox.",
    description: "Empty state body for notification inbox rows.",
  },
  "notifications.table.ariaLabel": {
    defaultMessage: "Notifications inbox",
    description: "Accessible table label for notification inbox rows.",
  },
  "notifications.table.actions": {
    defaultMessage: "Actions",
    description: "Column header for notification row actions.",
  },
  "notifications.action.markRead": {
    defaultMessage: "Mark read",
    description: "Button label to mark a notification read.",
  },
  "notifications.action.markReadAria": {
    defaultMessage: "Mark notification {id} read",
    description: "Accessible label to mark a notification read.",
  },
  "notifications.action.requeue": {
    defaultMessage: "Requeue",
    description: "Button label to requeue a dead-letter notification.",
  },
  "notifications.action.requeueAria": {
    defaultMessage: "Requeue notification {id}",
    description: "Accessible label to requeue a notification.",
  },
  "incidents.playbooks.heading": {
    defaultMessage: "Automated remediation playbooks",
    description: "Heading for the incident remediation playbook section.",
  },
  "incidents.playbooks.description": {
    defaultMessage: "Run revoke, rotate, and right-size playbooks with auditable evidence and queued external actions.",
    description: "Description for the incident remediation playbook section.",
  },
  "incidents.playbooks.targetIdentity": {
    defaultMessage: "Target identity",
    description: "Label for target identity input on the remediation playbook form.",
  },
  "incidents.playbooks.inventoryId": {
    defaultMessage: "Inventory ID",
    description: "Label for inventory id input on the remediation playbook form.",
  },
  "incidents.playbooks.connector": {
    defaultMessage: "Playbook delivery method",
    description: "Label for remediation connector input and table column.",
  },
  "incidents.playbooks.providerTarget": {
    defaultMessage: "Provider target",
    description: "Label for provider target input on the remediation playbook form.",
  },
  "incidents.playbooks.removeScopes": {
    defaultMessage: "Remove scopes",
    description: "Label for scopes to remove in an NHI right-size run.",
  },
  "incidents.playbooks.rollbackReference": {
    defaultMessage: "Playbook rollback instructions",
    description: "Label for rollback reference input on the remediation playbook form.",
  },
  "incidents.playbooks.reason": {
    defaultMessage: "Reason",
    description: "Label for remediation playbook reason input.",
  },
  "incidents.playbooks.defaultReason": {
    defaultMessage: "right-size unused grants",
    description: "Default reason for a right-size remediation playbook run.",
  },
  "incidents.playbooks.inventoryPlaceholder": {
    defaultMessage: "identity/... or finding/...",
    description: "Placeholder for remediation playbook inventory id input.",
  },
  "incidents.playbooks.connectorPlaceholder": {
    defaultMessage: "aws-iam",
    description: "Placeholder for remediation playbook connector input.",
  },
  "incidents.playbooks.providerTargetPlaceholder": {
    defaultMessage: "role, service account, secret path",
    description: "Placeholder for remediation playbook provider target input.",
  },
  "incidents.playbooks.removeScopesPlaceholder": {
    defaultMessage: "optional comma-separated subset",
    description: "Placeholder for right-size scope removal input.",
  },
  "incidents.playbooks.rollbackPlaceholder": {
    defaultMessage: "restore previous policy version",
    description: "Placeholder for remediation playbook rollback reference input.",
  },
  "incidents.playbooks.runRightSize": {
    defaultMessage: "Run right-size",
    description: "Button label for starting an NHI right-size playbook.",
  },
  "incidents.playbooks.running": {
    defaultMessage: "Running...",
    description: "Busy button label while a playbook run is being requested.",
  },
  "incidents.playbooks.failedTitle": {
    defaultMessage: "Playbook run failed",
    description: "Error title when a remediation playbook run fails.",
  },
  "incidents.playbooks.requiredTarget": {
    defaultMessage: "Target identity or inventory ID is required.",
    description: "Validation error when no target was entered for a playbook run.",
  },
  "incidents.playbooks.loadError": {
    defaultMessage: "Could not run remediation playbook",
    description: "Fallback error when a playbook run request fails.",
  },
  "incidents.playbooks.recorded": {
    defaultMessage: "Playbook run recorded",
    description: "Status heading after a remediation playbook run is recorded.",
  },
  "incidents.playbooks.run": {
    defaultMessage: "Run",
    description: "Short label for a remediation playbook run id.",
  },
  "incidents.playbooks.playbook": {
    defaultMessage: "Playbook",
    description: "Short label for a remediation playbook id.",
  },
  "incidents.playbooks.status": {
    defaultMessage: "Status",
    description: "Short label for remediation playbook run status.",
  },
  "incidents.playbooks.externalIntent": {
    defaultMessage: "External intent",
    description: "Short label for remediation playbook external intent evidence.",
  },
  "incidents.playbooks.noRuns": {
    defaultMessage: "No remediation playbook runs have been recorded.",
    description: "Empty state for remediation playbook run table.",
  },
  "incidents.playbooks.tableCaption": {
    defaultMessage: "Remediation playbook run evidence",
    description: "Accessible caption for remediation playbook run table.",
  },
  "incidents.playbooks.target": {
    defaultMessage: "Target",
    description: "Short table-column label for playbook target.",
  },
  "incidents.playbooks.rollback": {
    defaultMessage: "Rollback",
    description: "Short table-column label for playbook rollback evidence.",
  },
  "incidents.playbooks.none": {
    defaultMessage: "none",
    description: "Fallback when a playbook run has no rollback refs.",
  },
  "incidents.ownerRemediation.heading": {
    defaultMessage: "Owner self-remediation",
    description: "Heading for owner-driven remediation actions.",
  },
  "incidents.ownerRemediation.description": {
    defaultMessage: "Owners can accept least-privilege recommendations from live posture evidence without broad incident authority.",
    description: "Description for owner-driven remediation actions.",
  },
  "incidents.ownerRemediation.summary": {
    defaultMessage: "{open} open / {accepted} accepted",
    description: "Summary of owner remediation queue state.",
  },
  "incidents.ownerRemediation.failedTitle": {
    defaultMessage: "Owner remediation failed",
    description: "Error title for owner-driven remediation failures.",
  },
  "incidents.ownerRemediation.loadError": {
    defaultMessage: "Could not accept owner remediation action",
    description: "Fallback error for owner remediation acceptance.",
  },
  "incidents.ownerRemediation.loading": {
    defaultMessage: "Loading owner actions...",
    description: "Loading text for owner remediation queue.",
  },
  "incidents.ownerRemediation.empty": {
    defaultMessage: "No owner self-remediation actions are open.",
    description: "Empty state for owner remediation queue.",
  },
  "incidents.ownerRemediation.caption": {
    defaultMessage: "Owner self-remediation actions",
    description: "Accessible caption for owner remediation table.",
  },
  "incidents.ownerRemediation.identity": {
    defaultMessage: "Identity",
    description: "Owner remediation table identity column.",
  },
  "incidents.ownerRemediation.severity": {
    defaultMessage: "Severity",
    description: "Owner remediation table severity column.",
  },
  "incidents.ownerRemediation.recommendation": {
    defaultMessage: "Recommendation",
    description: "Owner remediation table recommendation column.",
  },
  "incidents.ownerRemediation.status": {
    defaultMessage: "Status",
    description: "Owner remediation table status column.",
  },
  "incidents.ownerRemediation.action": {
    defaultMessage: "Action",
    description: "Owner remediation table action column.",
  },
  "incidents.ownerRemediation.accept": {
    defaultMessage: "Accept",
    description: "Button label to accept an owner remediation action.",
  },
  "incidents.ownerRemediation.accepting": {
    defaultMessage: "Accepting...",
    description: "Busy label while accepting an owner remediation action.",
  },
  "incidents.ownerRemediation.accepted": {
    defaultMessage: "Accepted",
    description: "Accepted state label for owner remediation action.",
  },
  "incidents.ownerRemediation.recorded": {
    defaultMessage: "Owner remediation recorded",
    description: "Status heading after an owner remediation action is accepted.",
  },
  "incidents.ownerRemediation.run": {
    defaultMessage: "Run",
    description: "Short label for owner remediation run id.",
  },
  "incidents.ownerRemediation.playbook": {
    defaultMessage: "Playbook",
    description: "Short label for owner remediation playbook id.",
  },
  "incidents.ownerRemediation.externalIntent": {
    defaultMessage: "External intent",
    description: "Short label for owner remediation external intent.",
  },
  "incidents.response.heading": {
    defaultMessage: "SIEM / SOAR / ITSM dispatch",
    description: "Heading for the incident response integration dispatch section.",
  },
  "incidents.response.description": {
    defaultMessage: "Send one response packet to Splunk, Jira, Slack, and ServiceNow through event-sourced outbox fan-out.",
    description: "Description for the incident response integration dispatch section.",
  },
  "incidents.response.title": {
    defaultMessage: "Response title",
    description: "Label for response integration dispatch title.",
  },
  "incidents.response.summary": {
    defaultMessage: "Response summary",
    description: "Label for response integration dispatch summary.",
  },
  "incidents.response.severity": {
    defaultMessage: "Severity",
    description: "Label for response integration dispatch severity.",
  },
  "incidents.response.correlation": {
    defaultMessage: "Correlation ID",
    description: "Label for response integration dispatch correlation id.",
  },
  "incidents.response.evidenceRefs": {
    defaultMessage: "Evidence references",
    description: "Label for response integration evidence references.",
  },
  "incidents.response.splunkEndpoint": {
    defaultMessage: "Splunk HEC endpoint",
    description: "Label for Splunk HEC endpoint input.",
  },
  "incidents.response.splunkToken": {
    defaultMessage: "Splunk token reference",
    description: "Label for Splunk token reference input.",
  },
  "incidents.response.jiraEndpoint": {
    defaultMessage: "Jira endpoint",
    description: "Label for Jira endpoint input.",
  },
  "incidents.response.jiraProject": {
    defaultMessage: "Jira project",
    description: "Label for Jira project key input.",
  },
  "incidents.response.jiraToken": {
    defaultMessage: "Jira token reference",
    description: "Label for Jira token reference input.",
  },
  "incidents.response.slackRoute": {
    defaultMessage: "Slack route",
    description: "Label for Slack routing policy or channel input.",
  },
  "incidents.response.servicenowInstance": {
    defaultMessage: "ServiceNow instance",
    description: "Label for ServiceNow instance URL input.",
  },
  "incidents.response.servicenowToken": {
    defaultMessage: "ServiceNow token reference",
    description: "Label for ServiceNow token reference input.",
  },
  "incidents.response.dispatch": {
    defaultMessage: "Dispatch response",
    description: "Button label for dispatching response integrations.",
  },
  "incidents.response.dispatching": {
    defaultMessage: "Dispatching...",
    description: "Busy button label while response integrations are queued.",
  },
  "incidents.response.failedTitle": {
    defaultMessage: "Response dispatch failed",
    description: "Error title when response integration dispatch fails.",
  },
  "incidents.response.titleRequired": {
    defaultMessage: "Response title is required.",
    description: "Validation error when response integration title is blank.",
  },
  "incidents.response.providersRequired": {
    defaultMessage: "Splunk, Jira, and ServiceNow endpoints are required.",
    description: "Validation error when required response integration endpoints are blank.",
  },
  "incidents.response.loadError": {
    defaultMessage: "Could not dispatch response integrations",
    description: "Fallback error when response integration dispatch fails.",
  },
  "incidents.response.queued": {
    defaultMessage: "Response dispatch queued",
    description: "Status heading after response integration dispatch is queued.",
  },
  "incidents.response.dispatchId": {
    defaultMessage: "Dispatch",
    description: "Short label for response integration dispatch id.",
  },
  "incidents.response.provider": {
    defaultMessage: "Provider",
    description: "Column label for response integration provider.",
  },
  "incidents.response.destination": {
    defaultMessage: "Destination",
    description: "Column label for response integration outbox destination.",
  },
  "incidents.response.outbox": {
    defaultMessage: "Outbox",
    description: "Short label for response integration outbox id.",
  },
  "incidents.response.status": {
    defaultMessage: "Status",
    description: "Short label for response integration status.",
  },
  "incidents.response.severityCritical": {
    defaultMessage: "critical",
    description: "Critical response severity option.",
  },
  "incidents.response.severityWarning": {
    defaultMessage: "warning",
    description: "Warning response severity option.",
  },
  "incidents.response.severityInformational": {
    defaultMessage: "informational",
    description: "Informational response severity option.",
  },
  "incidents.response.severityLow": {
    defaultMessage: "low",
    description: "Low response severity option.",
  },
  "incidents.response.idempotency": {
    defaultMessage: "Idempotency",
    description: "Short label for response integration idempotency key.",
  },
  "incidents.response.tableCaption": {
    defaultMessage: "Response integration destinations",
    description: "Accessible caption for response integration queued destinations.",
  },
  "incidents.response.titlePlaceholder": {
    defaultMessage: "Contain compromised payments credential",
    description: "Placeholder for response integration dispatch title.",
  },
  "incidents.response.optionalPlaceholder": {
    defaultMessage: "optional",
    description: "Placeholder for optional response integration fields.",
  },
  "incidents.response.evidencePlaceholder": {
    defaultMessage: "incident/... , audit/...",
    description: "Placeholder for response integration evidence references.",
  },
  "incidents.response.splunkPlaceholder": {
    defaultMessage: "https://splunk.example/services/collector",
    description: "Placeholder for Splunk HEC endpoint URL.",
  },
  "incidents.response.jiraPlaceholder": {
    defaultMessage: "https://jira.example",
    description: "Placeholder for Jira endpoint URL.",
  },
  "incidents.response.servicenowPlaceholder": {
    defaultMessage: "https://example.service-now.com",
    description: "Placeholder for ServiceNow instance URL.",
  },
  "connectors.deliveryEvidence": {
    defaultMessage: "Connector delivery evidence",
    description: "Heading for served connector registry and delivery receipt evidence.",
  },
  "platform.scale.heading": {
    defaultMessage: "Scale orchestration",
    description: "Heading for the high-volume orchestration posture panel.",
  },
  "platform.scale.served": {
    defaultMessage: "CAP-SCALE-01 active",
    description: "Badge showing that the scale orchestration capability is active.",
  },
  "platform.scale.unavailable": {
    defaultMessage: "scale unavailable",
    description: "Badge shown when scale orchestration posture is unavailable.",
  },
  "platform.scale.selectedTier": {
    defaultMessage: "Selected tier",
    description: "Metric label for the selected capacity tier.",
  },
  "platform.scale.credentialsCount": {
    defaultMessage: "{count} credentials",
    description: "Credential count within the selected capacity tier.",
  },
  "platform.scale.eventsPerDay": {
    defaultMessage: "Events/day",
    description: "Metric label for estimated daily event volume.",
  },
  "platform.scale.monthlyCost": {
    defaultMessage: "Monthly cost model",
    description: "Metric label for estimated monthly operating cost.",
  },
  "platform.scale.unitCost": {
    defaultMessage: "Unit cost",
    description: "Metric label for cost per managed credential.",
  },
  "platform.scale.credentialUnit": {
    defaultMessage: "credential",
    description: "Unit label for cost per managed credential.",
  },
  "platform.scale.signerModel": {
    defaultMessage: "Signer model",
    description: "Metric label for the signing service process posture.",
  },
  "platform.scale.projectionFloor": {
    defaultMessage: "Projection floor",
    description: "Metric label for projection replay floor and lag.",
  },
  "platform.scale.projectionFloorValue": {
    defaultMessage: "{rate} events/sec · lag ≤ {lag}",
    description: "Projection replay throughput and maximum lag summary.",
  },
  "platform.scale.executionCaption": {
    defaultMessage: "Scale execution lane table",
    description: "Accessible caption for scale execution lanes.",
  },
  "platform.scale.lane": {
    defaultMessage: "Lane",
    description: "Scale execution lane table column.",
  },
  "platform.scale.bulkhead": {
    defaultMessage: "Bulkhead",
    description: "Scale execution lane bulkhead table column.",
  },
  "platform.scale.signal": {
    defaultMessage: "Signal",
    description: "Scale execution lane backpressure signal table column.",
  },
  "platform.scale.slo": {
    defaultMessage: "SLO",
    description: "Scale execution lane SLO table column.",
  },
  "platform.scale.releaseCaption": {
    defaultMessage: "Scale release gate table",
    description: "Accessible caption for scale release gates.",
  },
  "platform.scale.gate": {
    defaultMessage: "Gate",
    description: "Scale release gate table column.",
  },
  "platform.scale.artifact": {
    defaultMessage: "Artifact",
    description: "Scale release gate artifact table column.",
  },
  "platform.scale.bandCaption": {
    defaultMessage: "Scale credential band table",
    description: "Accessible caption for scale credential bands.",
  },
  "platform.scale.band": {
    defaultMessage: "Band",
    description: "Scale credential band table column.",
  },
  "platform.scale.tier": {
    defaultMessage: "Tier",
    description: "Scale credential band tier table column.",
  },
  "platform.ha.heading": {
    defaultMessage: "Regional issuance HA",
    description: "Heading for the multi-region high-availability issuance panel.",
  },
  "platform.ha.active": {
    defaultMessage: "CAP-SCALE-02 active",
    description: "Badge showing that regional HA issuance is active.",
  },
  "platform.ha.unavailable": {
    defaultMessage: "regional issuance unavailable",
    description: "Badge shown when regional HA issuance posture is unavailable.",
  },
  "platform.ha.description": {
    defaultMessage:
      "Regional ingress can accept issuance traffic while idempotency, event append, outbox, leader election, and signer isolation keep each tenant mutation fenced.",
    description: "Short description of the regional HA issuance safety model.",
  },
  "platform.ha.topology": {
    defaultMessage: "Topology",
    description: "Metric label for regional issuance topology.",
  },
  "platform.ha.writeModel": {
    defaultMessage: "Write model",
    description: "Metric label for regional issuance write model.",
  },
  "platform.ha.rpoRto": {
    defaultMessage: "RPO / RTO",
    description: "Metric label for recovery point and recovery time objectives.",
  },
  "platform.ha.rpoRtoValue": {
    defaultMessage: "RPO {rpo}s · RTO {rto}s",
    description: "Regional issuance recovery point and time objectives.",
  },
  "platform.ha.invariants": {
    defaultMessage: "Architecture invariants",
    description: "Metric label for architecture invariants preserved by regional issuance.",
  },
  "platform.ha.regionCaption": {
    defaultMessage: "Regional issuance ingress table",
    description: "Accessible caption for regional issuance ingress rows.",
  },
  "platform.ha.region": {
    defaultMessage: "Region",
    description: "Regional issuance table region column.",
  },
  "platform.ha.role": {
    defaultMessage: "Role",
    description: "Regional issuance table role column.",
  },
  "platform.ha.writeScope": {
    defaultMessage: "Write scope",
    description: "Regional issuance table write-scope column.",
  },
  "platform.ha.health": {
    defaultMessage: "Health signal",
    description: "Regional issuance table health-signal column.",
  },
  "platform.ha.fenceCaption": {
    defaultMessage: "Regional issuance write-fence table",
    description: "Accessible caption for regional issuance write fences.",
  },
  "platform.ha.fence": {
    defaultMessage: "Fence",
    description: "Regional issuance fence table fence column.",
  },
  "platform.ha.scope": {
    defaultMessage: "Scope",
    description: "Regional issuance fence table scope column.",
  },
  "platform.ha.mechanism": {
    defaultMessage: "Mechanism",
    description: "Regional issuance fence table mechanism column.",
  },
  "platform.ha.failoverCaption": {
    defaultMessage: "Regional issuance failover table",
    description: "Accessible caption for regional issuance failover steps.",
  },
  "platform.ha.step": {
    defaultMessage: "Step",
    description: "Regional issuance failover table step column.",
  },
  "platform.ha.action": {
    defaultMessage: "Action",
    description: "Regional issuance failover table action column.",
  },
  "platform.ha.gate": {
    defaultMessage: "Gate",
    description: "Regional issuance failover table gate column.",
  },
  "protocols.dns01.heading": {
    defaultMessage: "DNS-01 providers",
    description: "Heading for the ACME DNS-01 provider catalog section.",
  },
  "protocols.dns01.caption": {
    defaultMessage: "ACME DNS-01 provider coverage",
    description: "Accessible caption for the DNS-01 provider catalog table.",
  },
  "protocols.dns01.provider": {
    defaultMessage: "Provider",
    description: "DNS-01 provider table column.",
  },
  "protocols.dns01.kind": {
    defaultMessage: "Kind",
    description: "DNS-01 provider kind table column.",
  },
  "protocols.dns01.conformance": {
    defaultMessage: "Conformance",
    description: "DNS-01 provider conformance table column.",
  },
  "protocols.dns01.admission": {
    defaultMessage: "Admission",
    description: "DNS-01 provider plugin admission label.",
  },
  "protocols.dns01.provenance": {
    defaultMessage: "Provenance",
    description: "DNS-01 provider plugin provenance label.",
  },
  "protocols.dns01.secretReferences": {
    defaultMessage: "Secret references",
    description: "DNS-01 provider credential reference table column.",
  },
  "protocols.dns01.capabilityGrant": {
    defaultMessage: "Capability grant",
    description: "DNS-01 provider capability grant table column.",
  },
  "protocols.dns01.propagationPreflight": {
    defaultMessage: "Propagation preflight",
    description: "DNS-01 provider propagation preflight label.",
  },
  "protocols.dns01.noRawSecretFields": {
    defaultMessage: "No raw secret fields",
    description: "DNS-01 provider no raw secret fields label.",
  },
  "protocols.dns01.loading": {
    defaultMessage: "Loading DNS-01 provider coverage.",
    description: "Loading message for DNS-01 provider catalog.",
  },
  "protocols.dns01.unavailableTitle": {
    defaultMessage: "DNS-01 providers unavailable",
    description: "Error title when DNS-01 provider catalog is empty.",
  },
  "protocols.dns01.empty": {
    defaultMessage: "No provider catalog rows were returned.",
    description: "Empty-state message for DNS-01 provider catalog.",
  },
  "protocols.dns01.served": {
    defaultMessage: "Available",
    description: "Badge label for a served DNS-01 provider.",
  },
  "protocols.dns01.off": {
    defaultMessage: "Off",
    description: "Badge label for an unavailable DNS-01 provider.",
  },
  "protocols.dns01.configHeading": {
    defaultMessage: "DNS-01 provider configs",
    description: "Heading for the tenant DNS-01 provider configuration section.",
  },
  "protocols.dns01.configCaption": {
    defaultMessage: "Tenant DNS-01 provider configurations",
    description: "Accessible caption for the DNS-01 provider configuration table.",
  },
  "protocols.dns01.config": {
    defaultMessage: "Config",
    description: "DNS-01 provider config table column.",
  },
  "protocols.dns01.zone": {
    defaultMessage: "Zone",
    description: "DNS-01 provider zone table column.",
  },
  "protocols.dns01.policy": {
    defaultMessage: "Policy",
    description: "DNS-01 provider policy table column.",
  },
  "protocols.dns01.zoneUnbound": {
    defaultMessage: "Zone unbound",
    description: "Fallback label when a DNS-01 provider config has no zone.",
  },
  "protocols.dns01.noMethodPolicy": {
    defaultMessage: "No method policy",
    description: "Fallback label when a DNS-01 provider config has no method policy.",
  },
  "protocols.dns01.wildcardsAllowed": {
    defaultMessage: "Wildcards allowed",
    description: "DNS-01 provider wildcard policy label.",
  },
  "protocols.dns01.wildcardsDenied": {
    defaultMessage: "Wildcards denied",
    description: "DNS-01 provider wildcard policy label.",
  },
  "protocols.dns01.configLoading": {
    defaultMessage: "Loading DNS-01 provider configs.",
    description: "Loading message for DNS-01 provider configuration table.",
  },
  "protocols.dns01.configEmptyTitle": {
    defaultMessage: "DNS-01 provider configs unavailable",
    description: "Empty-state title for DNS-01 provider configuration table.",
  },
  "protocols.dns01.configEmpty": {
    defaultMessage: "No provider configs were returned.",
    description: "Empty-state message for DNS-01 provider configuration table.",
  },
  "protocols.mdm.heading": {
    defaultMessage: "Intune / MDM SCEP policies",
    description: "Heading for the MDM SCEP enrollment policy section.",
  },
  "protocols.mdm.caption": {
    defaultMessage: "MDM SCEP enrollment policies",
    description: "Accessible caption for the MDM SCEP policy table.",
  },
  "protocols.mdm.policy": {
    defaultMessage: "Policy",
    description: "MDM SCEP policy table column.",
  },
  "protocols.mdm.provider": {
    defaultMessage: "Provider",
    description: "MDM SCEP provider table column.",
  },
  "protocols.mdm.profile": {
    defaultMessage: "Profile",
    description: "MDM SCEP profile table column.",
  },
  "protocols.mdm.challenge": {
    defaultMessage: "Challenge",
    description: "MDM SCEP challenge policy table column.",
  },
  "protocols.mdm.references": {
    defaultMessage: "References",
    description: "MDM SCEP reference fields table column.",
  },
  "protocols.mdm.enabled": {
    defaultMessage: "Enabled",
    description: "Badge label for enabled MDM SCEP policy.",
  },
  "protocols.mdm.disabled": {
    defaultMessage: "Disabled",
    description: "Badge label for disabled MDM SCEP policy.",
  },
  "protocols.mdm.rotationVersion": {
    defaultMessage: "Rotation version",
    description: "MDM SCEP policy rotation-version label.",
  },
  "protocols.mdm.telemetry": {
    defaultMessage: "Challenge telemetry",
    description: "MDM SCEP challenge telemetry panel heading.",
  },
  "protocols.mdm.allowed": {
    defaultMessage: "Allowed",
    description: "Allowed MDM SCEP challenge count label.",
  },
  "protocols.mdm.denied": {
    defaultMessage: "Denied",
    description: "Denied MDM SCEP challenge count label.",
  },
  "protocols.mdm.replay": {
    defaultMessage: "Replay",
    description: "Replay-rejected MDM SCEP challenge count label.",
  },
  "protocols.mdm.runtime": {
    defaultMessage: "Runtime",
    description: "MDM SCEP runtime gate label.",
  },
  "protocols.mdm.runtimeConfigured": {
    defaultMessage: "Configured",
    description: "MDM SCEP runtime gate configured label.",
  },
  "protocols.mdm.runtimeUnknown": {
    defaultMessage: "Unknown",
    description: "MDM SCEP runtime gate unknown label.",
  },
  "protocols.mdm.loading": {
    defaultMessage: "Loading MDM SCEP policies.",
    description: "Loading message for MDM SCEP policy table.",
  },
  "protocols.mdm.emptyTitle": {
    defaultMessage: "MDM SCEP policies unavailable",
    description: "Empty-state title for MDM SCEP policies.",
  },
  "protocols.mdm.empty": {
    defaultMessage: "No MDM SCEP policies were returned.",
    description: "Empty-state message for MDM SCEP policies.",
  },
  "secrets.scan.description": {
    defaultMessage: "Run a scan for a repository or build workspace. Findings show rule, file, line, and the redacted credential reference only.",
    description: "Description for the Code and CI secret scanning bridge panel.",
  },
  "secrets.scan.triageLibraryOnlyTitle": {
    defaultMessage: "Scan finding review is not available yet",
    description: "Unavailable-state title for scan finding triage workflows that are not served yet.",
  },
  "secrets.scan.triageLibraryOnlyBody": {
    defaultMessage:
      "Repository events and scans can create redacted findings here. Use the discovery workflow to review them until scan-specific actions are added.",
    description: "Unavailable-state body for scan finding triage workflows that are not served yet.",
  },
  "secrets.scan.mode": {
    defaultMessage: "Mode",
    description: "Label for selecting workspace or Git-history secret-scan mode.",
  },
  "secrets.scan.modeWorkspace": {
    defaultMessage: "Workspace",
    description: "Secret-scan mode label for scanning the current workspace filesystem.",
  },
  "secrets.scan.modeGitHistory": {
    defaultMessage: "Git history",
    description: "Secret-scan mode label for scanning full Git history.",
  },
  "secrets.scan.customRules": {
    defaultMessage: "Custom rules",
    description: "Label for additive custom Gitleaks rule fragments.",
  },
  "secrets.scan.customRulesPlaceholder": {
    defaultMessage: "/etc/trstctl/gitleaks-rules.toml",
    description: "Placeholder path for an additive custom Gitleaks rules file.",
  },
  "secrets.scan.customRulesYes": {
    defaultMessage: "yes",
    description: "Short value showing custom rules were used for a secret scan.",
  },
  "secrets.scan.customRulesNo": {
    defaultMessage: "no",
    description: "Short value showing custom rules were not used for a secret scan.",
  },
  "secrets.approvals.heading": {
    defaultMessage: "Secret-change approvals",
    description: "Heading for the secret-change approval queue.",
  },
  "secrets.approvals.description": {
    defaultMessage: "Denied rotate/update/delete requests appear here for distinct approver review.",
    description: "Description for the secret-change approval queue.",
  },
  "secrets.approvals.badge": {
    defaultMessage: "Dual control",
    description: "Badge label for the secret-change approval queue.",
  },
  "secrets.approvals.empty": {
    defaultMessage: "No pending secret changes captured in this browser session.",
    description: "Empty-state message for the secret-change approval queue.",
  },
  "secrets.approvals.listLabel": {
    defaultMessage: "Pending secret-change approvals",
    description: "Accessible label for the secret-change approval list.",
  },
  "secrets.approvals.errorTitle": {
    defaultMessage: "Approval state",
    description: "Error-state title inside one pending secret-change approval row.",
  },
  "secrets.approvals.actionRotate": {
    defaultMessage: "Rotate/update",
    description: "Secret-change approval action label for a rotation/update.",
  },
  "secrets.approvals.actionRecover": {
    defaultMessage: "Recover",
    description: "Secret-change approval action label for a recovery.",
  },
  "secrets.approvals.actionDelete": {
    defaultMessage: "Delete",
    description: "Secret-change approval action label for a deletion.",
  },
  "secrets.approvals.openedStatus": {
    defaultMessage: "Opened {openedAt} - {status}",
    description: "Timestamp and current status for one pending secret-change approval row.",
  },
  "secrets.approvals.statusCompleted": {
    defaultMessage: "completed",
    description: "Status text for a completed secret-change approval.",
  },
  "secrets.approvals.statusApproved": {
    defaultMessage: "approved",
    description: "Status text for an approved secret-change approval.",
  },
  "secrets.approvals.statusApprovedBy": {
    defaultMessage: "approved by {approver}",
    description: "Status text for an approved secret-change approval with approver name.",
  },
  "secrets.approvals.statusApprovedWithCount": {
    defaultMessage: "approved by {approver} ({count} approvals recorded)",
    description: "Status text for an approved secret-change approval with approver name and count.",
  },
  "secrets.approvals.statusCount": {
    defaultMessage: "{count} approvals recorded",
    description: "Status text for a pending secret-change approval with a known approval count.",
  },
  "secrets.approvals.statusAwaiting": {
    defaultMessage: "awaiting distinct approval",
    description: "Status text for a secret-change approval awaiting approval.",
  },
  "secrets.approvals.approve": {
    defaultMessage: "Approve",
    description: "Button label for approving a secret-change request.",
  },
  "secrets.approvals.retry": {
    defaultMessage: "Retry",
    description: "Button label for retrying an approved secret-change request.",
  },
  "secrets.approvals.approveAction": {
    defaultMessage: "Approve {action} for {name}",
    description: "Accessible label for approving a secret-change request.",
  },
  "secrets.approvals.retryAction": {
    defaultMessage: "Retry {action} for {name}",
    description: "Accessible label for retrying an approved secret-change request.",
  },
  "secrets.approvals.requiredFallback": {
    defaultMessage: "Secret change requires dual-control approval",
    description: "Fallback error text when a secret change is denied for missing approval.",
  },
  "secrets.approvals.approvedNotice": {
    defaultMessage: "{approver} approved {action} for {name}. Retry the change to complete it.",
    description: "Success notice after recording a secret-change approval.",
  },
  "secrets.approvals.approveFailed": {
    defaultMessage: "Could not approve secret change",
    description: "Fallback error when approval recording fails.",
  },
  "secrets.approvals.retryFailed": {
    defaultMessage: "Could not retry approved secret change",
    description: "Fallback error when retrying an approved secret change fails.",
  },
  "secrets.approvals.rotateRetryNeedsForm": {
    defaultMessage: "Keep the rotation form on {name} with a replacement value before retrying.",
    description: "Validation error shown when a rotate retry lacks the current replacement value.",
  },
  "secrets.approvals.deleteRetryNeedsForm": {
    defaultMessage: "Confirm {name} in the delete form before retrying.",
    description: "Validation error shown when a delete retry lacks the delete confirmation.",
  },
  "secrets.approvals.recoverRetryUnsupported": {
    defaultMessage: "Recover approval is recorded; retry recovery through the recover endpoint.",
    description: "Fallback for recovery approvals not retried by this console form.",
  },
  "secrets.approvals.rotatePending": {
    defaultMessage: "Rotation is waiting for secret-change approval.",
    description: "Inline error when a rotate request opens a secret-change approval.",
  },
  "secrets.approvals.deletePending": {
    defaultMessage: "Delete is waiting for secret-change approval.",
    description: "Inline error when a delete request opens a secret-change approval.",
  },
  "secrets.approvals.rotatedAfterApproval": {
    defaultMessage: "Secret {name} rotated to version {version} after approval.",
    description: "Success notice after a secret rotate retry completes.",
  },
  "secrets.approvals.deletedAfterApproval": {
    defaultMessage: "Secret {name} deleted after approval.",
    description: "Success notice after a secret delete retry completes.",
  },
  "secrets.cloudManagers.coverage": {
    defaultMessage: "{discovery} discovery providers, {sync} sync targets configured",
    description: "Summary count for cloud secret-manager discovery and sync integration coverage.",
  },
  "secrets.cloudManagers.caption": {
    defaultMessage: "Cloud secret-manager integration coverage",
    description: "Accessible caption for the cloud secret-manager integration table.",
  },
  "secrets.cloudManagers.provider": {
    defaultMessage: "Provider",
    description: "Cloud secret-manager provider column.",
  },
  "secrets.cloudManagers.discovery": {
    defaultMessage: "Discovery",
    description: "Cloud secret-manager discovery status column.",
  },
  "secrets.cloudManagers.sync": {
    defaultMessage: "Sync",
    description: "Cloud secret-manager sync status column.",
  },
  "secrets.cloudManagers.handling": {
    defaultMessage: "Handling",
    description: "Cloud secret-manager secret-handling column.",
  },
  "secrets.cloudManagers.discoveryConfigured": {
    defaultMessage: "{count} source configured",
    description: "Cloud secret-manager discovery source count.",
  },
  "secrets.cloudManagers.discoveryAvailable": {
    defaultMessage: "read-only discovery available",
    description: "Cloud secret-manager discovery is supported but not configured.",
  },
  "secrets.cloudManagers.syncConfigured": {
    defaultMessage: "sync configured",
    description: "Cloud secret-manager sync target is configured.",
  },
  "secrets.cloudManagers.syncAvailable": {
    defaultMessage: "sync available",
    description: "Cloud secret-manager sync is supported but not configured.",
  },
  "secrets.cloudManagers.notSupported": {
    defaultMessage: "not supported",
    description: "Cloud secret-manager operation is not supported for this provider.",
  },
  "secrets.sync.catalogCaption": {
    defaultMessage: "Secret sync provider catalog",
    description: "Accessible caption for the secret-sync provider catalog table.",
  },
  "secrets.sync.configuredCount": {
    defaultMessage: "{count} configured",
    description: "Summary count of configured secret-sync targets.",
  },
  "secrets.sync.target": {
    defaultMessage: "Target",
    description: "Secret-sync provider catalog target column.",
  },
  "secrets.sync.platform": {
    defaultMessage: "Platform",
    description: "Secret-sync provider catalog platform column.",
  },
  "secrets.sync.status": {
    defaultMessage: "Status",
    description: "Secret-sync provider catalog status column.",
  },
  "secrets.sync.delivery": {
    defaultMessage: "Delivery",
    description: "Secret-sync provider catalog delivery-mode column.",
  },
  "secrets.sync.configured": {
    defaultMessage: "configured",
    description: "Secret-sync target is configured.",
  },
  "secrets.sync.available": {
    defaultMessage: "available",
    description: "Secret-sync target is supported but not configured.",
  },
  "secrets.sync.operatorCoverage": {
    defaultMessage: "Kubernetes operator CRD sync and reload coverage",
    description: "Summary label for the Kubernetes SecretSync operator posture panel.",
  },
  "secrets.sync.operatorCRDs": {
    defaultMessage: "Custom resources",
    description: "Heading for Kubernetes SecretSync operator CRDs.",
  },
  "secrets.sync.operatorReloadWorkloads": {
    defaultMessage: "Auto-reload workloads",
    description: "Heading for workload kinds the Kubernetes SecretSync operator can reload.",
  },
  "secrets.sync.injectionCoverage": {
    defaultMessage: "No-code workload secret-injection coverage",
    description: "Summary label for the workload secret-injection posture panel.",
  },
  "secrets.sync.injectionCRD": {
    defaultMessage: "Injection resource",
    description: "Heading for the TrstctlSecretInjection custom resource.",
  },
  "secrets.sync.injectionModes": {
    defaultMessage: "Injection modes",
    description: "Heading for workload secret-injection modes.",
  },
  "secrets.sync.injectionWorkloads": {
    defaultMessage: "Injected workloads",
    description: "Heading for workload kinds supported by secret injection.",
  },
  "secrets.sync.unvaultedCoverage": {
    defaultMessage: "{findings} leaked findings, {vaults} vaults visible, {sync} sync targets configured",
    description: "Summary label for unvaulted-secret detection and multi-vault visibility.",
  },
  "secrets.sync.unvaultedDetection": {
    defaultMessage: "Detection sources",
    description: "Heading for unvaulted-secret detection source counts.",
  },
  "secrets.sync.unvaultedVaults": {
    defaultMessage: "Visible vaults",
    description: "Heading for cloud secret-manager and vault visibility.",
  },
  "secrets.sync.unvaultedSyncTargets": {
    defaultMessage: "Augmentation targets",
    description: "Heading for configured secret sync targets used for vault augmentation.",
  },
  "secrets.repoScan.active": {
    defaultMessage: "Realtime repository ingress active",
    description: "Status text when repository secret scanning ingress is served.",
  },
  "secrets.repoScan.unavailable": {
    defaultMessage: "Repository ingress unavailable",
    description: "Status text when repository secret scanning ingress is not served.",
  },
  "secrets.repoScan.ruleFloor": {
    defaultMessage: "{scanner} with {rules}+ required rules",
    description: "Scanner and rule-floor summary for repository secret scanning.",
  },
  "secrets.repoScan.providerCaption": {
    defaultMessage: "Repository secret scanning providers",
    description: "Accessible caption for the repository secret scanning provider table.",
  },
  "secrets.repoScan.provider": {
    defaultMessage: "Provider",
    description: "Repository secret scanning provider table header.",
  },
  "secrets.repoScan.triggers": {
    defaultMessage: "Triggers",
    description: "Repository secret scanning provider table header for realtime events.",
  },
  "secrets.repoScan.ingress": {
    defaultMessage: "Ingress",
    description: "Repository secret scanning provider table header for ingress mode.",
  },
  "secrets.repoScan.outbox": {
    defaultMessage: "Outbox",
    description: "Repository secret scanning provider table header for outbox mode.",
  },
  "secrets.repoScan.webhookPaths": {
    defaultMessage: "Webhook paths",
    description: "Label for repository secret scanning webhook path list.",
  },
  "secrets.repoScan.eventFlow": {
    defaultMessage: "Event flow",
    description: "Label for repository secret scanning event flow list.",
  },
  "secrets.repoScan.releaseGates": {
    defaultMessage: "Release gates",
    description: "Label for repository secret scanning release gates.",
  },
  "secrets.repoScan.residuals": {
    defaultMessage: "Residuals",
    description: "Label for repository secret scanning known residual shortfalls.",
  },
  "secrets.thirdPartyScan.active": {
    defaultMessage: "Third-party artifact scanning active",
    description: "Status text when CAP-SCAN-04 third-party artifact secret scanning is served.",
  },
  "secrets.thirdPartyScan.unavailable": {
    defaultMessage: "Third-party artifact scanning unavailable",
    description: "Status text when CAP-SCAN-04 third-party artifact secret scanning is not served.",
  },
  "secrets.thirdPartyScan.providerCaption": {
    defaultMessage: "Third-party secret scanning providers",
    description: "Accessible caption for the CAP-SCAN-04 provider table.",
  },
  "secrets.thirdPartyScan.artifactKinds": {
    defaultMessage: "Artifact kinds",
    description: "CAP-SCAN-04 provider table header for supported artifact kinds.",
  },
  "secrets.thirdPartyScan.ingestPaths": {
    defaultMessage: "Ingest paths",
    description: "Label for CAP-SCAN-04 ingest path list.",
  },
  "secrets.thirdPartyScan.form": {
    defaultMessage: "Queue third-party secret scan",
    description: "Accessible label for the CAP-SCAN-04 ingest form.",
  },
  "secrets.thirdPartyScan.provider": {
    defaultMessage: "External source",
    description: "Label for CAP-SCAN-04 provider select.",
  },
  "secrets.thirdPartyScan.source": {
    defaultMessage: "Source ref",
    description: "Label for CAP-SCAN-04 source reference input.",
  },
  "secrets.thirdPartyScan.sourcePlaceholder": {
    defaultMessage: "github-actions/payments#982",
    description: "Placeholder for CAP-SCAN-04 source reference.",
  },
  "secrets.thirdPartyScan.artifactPath": {
    defaultMessage: "Artifact path",
    description: "Label for CAP-SCAN-04 artifact path input.",
  },
  "secrets.thirdPartyScan.artifactPlaceholder": {
    defaultMessage: "/var/lib/trstctl/exports/slack.jsonl",
    description: "Placeholder for CAP-SCAN-04 artifact path.",
  },
  "secrets.thirdPartyScan.event": {
    defaultMessage: "Event",
    description: "Label for optional CAP-SCAN-04 event input.",
  },
  "secrets.thirdPartyScan.eventPlaceholder": {
    defaultMessage: "workflow_run",
    description: "Placeholder for optional CAP-SCAN-04 event input.",
  },
  "secrets.thirdPartyScan.queueing": {
    defaultMessage: "Queueing",
    description: "Button label while CAP-SCAN-04 ingest is in flight.",
  },
  "secrets.thirdPartyScan.queue": {
    defaultMessage: "Queue scan",
    description: "Button label for CAP-SCAN-04 ingest.",
  },
  "secrets.thirdPartyScan.errorTitle": {
    defaultMessage: "Third-party scan failed",
    description: "Error title for CAP-SCAN-04 ingest failure.",
  },
  "secrets.thirdPartyScan.accepted": {
    defaultMessage: "{provider} scan queued as run {run}",
    description: "Success status after CAP-SCAN-04 ingest is accepted.",
  },
  "workloads.kubernetesCSR.heading": {
    defaultMessage: "Kubernetes CertificateSigningRequest controller",
    description: "Heading for native Kubernetes CSR support posture on the Workloads page.",
  },
  "workloads.kubernetesCSR.description": {
    defaultMessage: "The agent signs approved native Kubernetes CSRs through the configured trstctl issue path and writes only CSR status back to the cluster.",
    description: "Description for native Kubernetes CSR controller posture.",
  },
  "workloads.kubernetesCSR.errorTitle": {
    defaultMessage: "Kubernetes CSR support unavailable",
    description: "Error title when the native Kubernetes CSR posture endpoint cannot be loaded.",
  },
  "workloads.kubernetesCSR.errorFallback": {
    defaultMessage: "Could not load Kubernetes CSR support",
    description: "Fallback error text for the native Kubernetes CSR posture endpoint.",
  },
  "workloads.kubernetesCSR.capability": {
    defaultMessage: "Capability",
    description: "Summary label for a capability identifier.",
  },
  "workloads.kubernetesCSR.apiGroup": {
    defaultMessage: "API group",
    description: "Summary label for a Kubernetes API group.",
  },
  "workloads.kubernetesCSR.resource": {
    defaultMessage: "Resource",
    description: "Summary label for a Kubernetes resource.",
  },
  "workloads.kubernetesCSR.generated": {
    defaultMessage: "Generated",
    description: "Summary label for report generation time.",
  },
  "workloads.kubernetesCSR.loading": {
    defaultMessage: "Loading",
    description: "Placeholder while the native Kubernetes CSR posture is loading.",
  },
  "workloads.kubernetesCSR.signerNames": {
    defaultMessage: "Signer names",
    description: "Heading for supported native Kubernetes CSR signer names.",
  },
  "workloads.kubernetesCSR.controllerControls": {
    defaultMessage: "Controller controls",
    description: "Heading for native Kubernetes CSR controller safeguards.",
  },
  "workloads.kubernetesCSR.rbac": {
    defaultMessage: "Kubernetes RBAC",
    description: "Heading for native Kubernetes CSR RBAC posture.",
  },
  "workloads.kubernetesCSR.statusFallback": {
    defaultMessage: "certificatesigningrequests/status: update, patch",
    description: "Fallback RBAC row for the native Kubernetes CSR status subresource.",
  },
  "workloads.kubernetesCSR.residuals": {
    defaultMessage: "Residuals",
    description: "Heading for native Kubernetes CSR residual shortfalls.",
  },
  "workloads.trustBundles.heading": {
    defaultMessage: "Kubernetes trust-bundle distribution",
    description: "Heading for Kubernetes trust-bundle distribution posture on the Workloads page.",
  },
  "workloads.trustBundles.description": {
    defaultMessage: "The agent distributes public CA bundles into namespace ConfigMaps from cluster-scoped TrustBundle resources.",
    description: "Description for Kubernetes trust-bundle distribution posture.",
  },
  "workloads.trustBundles.errorTitle": {
    defaultMessage: "Trust-bundle support unavailable",
    description: "Error title when the Kubernetes trust-bundle posture endpoint cannot be loaded.",
  },
  "workloads.trustBundles.errorFallback": {
    defaultMessage: "Could not load Kubernetes trust-bundle support",
    description: "Fallback error text for the Kubernetes trust-bundle posture endpoint.",
  },
  "workloads.trustBundles.capability": {
    defaultMessage: "Capability",
    description: "Summary label for a capability identifier.",
  },
  "workloads.trustBundles.apiGroup": {
    defaultMessage: "API group",
    description: "Summary label for a Kubernetes API group.",
  },
  "workloads.trustBundles.resource": {
    defaultMessage: "Resource",
    description: "Summary label for a Kubernetes resource.",
  },
  "workloads.trustBundles.generated": {
    defaultMessage: "Generated",
    description: "Summary label for report generation time.",
  },
  "workloads.trustBundles.loading": {
    defaultMessage: "Loading",
    description: "Placeholder while Kubernetes trust-bundle posture is loading.",
  },
  "workloads.trustBundles.targets": {
    defaultMessage: "Distribution targets",
    description: "Heading for Kubernetes trust-bundle target surfaces.",
  },
  "workloads.trustBundles.controllerControls": {
    defaultMessage: "Controller controls",
    description: "Heading for Kubernetes trust-bundle controller safeguards.",
  },
  "workloads.trustBundles.rbac": {
    defaultMessage: "Kubernetes RBAC",
    description: "Heading for Kubernetes trust-bundle RBAC posture.",
  },
  "workloads.trustBundles.statusFallback": {
    defaultMessage: "trustbundles/status: update, patch",
    description: "Fallback RBAC row for the Kubernetes TrustBundle status subresource.",
  },
  "workloads.trustBundles.statusFields": {
    defaultMessage: "Status fields",
    description: "Heading for Kubernetes TrustBundle status fields.",
  },
  "workloads.trustBundles.residuals": {
    defaultMessage: "Residuals",
    description: "Heading for Kubernetes trust-bundle residual shortfalls.",
  },
  "workloads.leases.heading": {
    defaultMessage: "Ephemeral credential leases",
    description: "Heading for the Workloads dynamic lease section.",
  },
  "workloads.leases.description": {
    defaultMessage: "A lease is a short promise: a workload proves who it is, receives one credential class, and loses it at expiry unless it re-attests.",
    description: "Description for ephemeral credential leases.",
  },
  "workloads.leases.timelineIssued": {
    defaultMessage: "00:00 issued",
    description: "Timeline marker for when an ephemeral credential lease is issued.",
  },
  "workloads.leases.timelineIssuedDescription": {
    defaultMessage: "policy and attestation digest bind the lease",
    description: "Timeline detail for issued ephemeral credential leases.",
  },
  "workloads.leases.timelineRenew": {
    defaultMessage: "00:45 renew window",
    description: "Timeline marker for when an ephemeral credential lease can renew.",
  },
  "workloads.leases.timelineRenewDescription": {
    defaultMessage: "workload must re-attest before renewal",
    description: "Timeline detail for renewing ephemeral credential leases.",
  },
  "workloads.leases.timelineExpires": {
    defaultMessage: "01:00 expires",
    description: "Timeline marker for when an ephemeral credential lease expires.",
  },
  "workloads.leases.timelineExpiresDescription": {
    defaultMessage: "credential is no longer trusted by policy",
    description: "Timeline detail for expired ephemeral credential leases.",
  },
  "workloads.leases.issueHeading": {
    defaultMessage: "Issue dynamic lease",
    description: "Form heading for issuing an ephemeral credential lease.",
  },
  "workloads.leases.issueDescription": {
    defaultMessage: "The API returns lease metadata only. If a provider returns credential material, this panel keeps it out of the browser table.",
    description: "Security note for the dynamic lease issue form.",
  },
  "workloads.leases.provider": {
    defaultMessage: "Provider",
    description: "Provider column and field label in the dynamic lease table.",
  },
  "workloads.leases.role": {
    defaultMessage: "Role",
    description: "Role column and field label in the dynamic lease table.",
  },
  "workloads.leases.ttlSeconds": {
    defaultMessage: "TTL seconds",
    description: "TTL field label for dynamic lease issuance.",
  },
  "workloads.leases.issueButton": {
    defaultMessage: "Issue lease",
    description: "Button label for issuing a dynamic lease.",
  },
  "workloads.leases.errorTitle": {
    defaultMessage: "Lease operation failed",
    description: "Error title for dynamic lease operations.",
  },
  "workloads.leases.leaseColumn": {
    defaultMessage: "Lease",
    description: "Lease ID table column heading.",
  },
  "workloads.leases.stateColumn": {
    defaultMessage: "State",
    description: "Lease state table column heading.",
  },
  "workloads.leases.issuedColumn": {
    defaultMessage: "Issued",
    description: "Lease issued-at table column heading.",
  },
  "workloads.leases.expiresColumn": {
    defaultMessage: "Expires",
    description: "Lease expiry table column heading.",
  },
  "workloads.leases.actionsColumn": {
    defaultMessage: "Actions",
    description: "Lease action table column heading.",
  },
  "workloads.leases.empty": {
    defaultMessage: "No lease has been issued in this browser session.",
    description: "Empty state text for the dynamic lease session table.",
  },
  "workloads.leases.renewButton": {
    defaultMessage: "Renew 5m",
    description: "Button label for renewing a lease by five minutes.",
  },
  "workloads.leases.revokeButton": {
    defaultMessage: "Revoke",
    description: "Button label for revoking a dynamic lease.",
  },
  "workloads.leases.revokeAria": {
    defaultMessage: "Revoke lease {id}",
    description: "Accessible label for revoking a specific dynamic lease.",
  },
  "workloads.leases.historyUnavailableTitle": {
    defaultMessage: "Lease history isn't in the console yet",
    description: "Unavailable-state title for tenant-wide lease history.",
  },
  "workloads.leases.historyUnavailableDescription": {
    defaultMessage:
      "The lease API can issue, read by ID, renew, and revoke. A tenant-wide lease list is not available in the browser contract yet, so this table shows leases returned during this session.",
    description: "Unavailable-state description for tenant-wide lease history.",
  },
  "workloads.leases.jitUnavailableTitle": {
    defaultMessage: "Ephemeral JIT issuance uses external approval flows",
    description: "Unavailable-state title for ephemeral JIT issuance approvals.",
  },
  "workloads.leases.jitUnavailableDescription": {
    defaultMessage:
      "Approval-gated ephemeral issuance is available outside this console. This console does not collect live proof payloads or approval actions.",
    description: "Unavailable-state description for ephemeral JIT issuance approvals.",
  },
  "workloads.attestation.heading": {
    defaultMessage: "Workload attestation chain",
    description: "Heading for workload attestation and trust-source controls.",
  },
  "workloads.attestation.description": {
    defaultMessage:
      "Attestation proves the workload and its platform. Submit a proof payload to issue an X.509-SVID, then keep only attestation metadata in the table.",
    description: "Description for workload attestation issuance.",
  },
  "workloads.attestation.trustSourceHeading": {
    defaultMessage: "Attester trust source",
    description: "Form heading for creating a workload attester trust source.",
  },
  "workloads.attestation.trustSourceName": {
    defaultMessage: "Trust source name",
    description: "Field label for the workload attester trust source name.",
  },
  "workloads.attestation.trustSourceMethod": {
    defaultMessage: "Trust source method",
    description: "Field label for the workload attester method.",
  },
  "workloads.attestation.method": {
    defaultMessage: "Attestation method",
    description: "Field label for attested SVID issuance method.",
  },
  "workloads.attestation.methodKubernetesServiceAccount": {
    defaultMessage: "Kubernetes service account",
    description: "Attester method label for Kubernetes service account tokens.",
  },
  "workloads.attestation.methodGithubOIDC": {
    defaultMessage: "GitHub OIDC",
    description: "Attester method label for GitHub OIDC.",
  },
  "workloads.attestation.methodAwsInstanceIdentity": {
    defaultMessage: "AWS instance identity",
    description: "Attester method label for AWS instance identity documents.",
  },
  "workloads.attestation.methodAzureIMDS": {
    defaultMessage: "Azure IMDS",
    description: "Attester method label for Azure instance metadata.",
  },
  "workloads.attestation.methodGcpInstanceIdentity": {
    defaultMessage: "GCP instance identity",
    description: "Attester method label for GCP instance identity tokens.",
  },
  "workloads.attestation.methodTpmQuote": {
    defaultMessage: "TPM quote",
    description: "Attester method label for TPM quotes.",
  },
  "workloads.attestation.issuer": {
    defaultMessage: "Issuer",
    description: "Field and column label for an attester issuer.",
  },
  "workloads.attestation.audience": {
    defaultMessage: "Audience",
    description: "Field label for an attester audience.",
  },
  "workloads.attestation.jwks": {
    defaultMessage: "Trust source JWKS JSON",
    description: "Field label for workload attester JWKS JSON.",
  },
  "workloads.attestation.rootCerts": {
    defaultMessage: "Trust source root certificate PEM",
    description: "Field label for workload attester root certificate PEM.",
  },
  "workloads.attestation.expectedNonce": {
    defaultMessage: "Expected nonce (base64)",
    description: "Field label for an expected attestation nonce.",
  },
  "workloads.attestation.enabled": {
    defaultMessage: "Enabled",
    description: "Checkbox label and status label for enabled trust sources.",
  },
  "workloads.attestation.createTrustSource": {
    defaultMessage: "Create trust source",
    description: "Button label for creating a workload attester trust source.",
  },
  "workloads.attestation.rotateHeading": {
    defaultMessage: "Rotate trust material",
    description: "Form heading for rotating workload attester trust material.",
  },
  "workloads.attestation.trustSource": {
    defaultMessage: "Trust source",
    description: "Field label for selecting a workload attester trust source.",
  },
  "workloads.attestation.noTrustSource": {
    defaultMessage: "No trust source",
    description: "Select placeholder when no workload attester trust source exists.",
  },
  "workloads.attestation.rotationJwks": {
    defaultMessage: "Rotation JWKS JSON",
    description: "Field label for rotated workload attester JWKS JSON.",
  },
  "workloads.attestation.rotationRootCerts": {
    defaultMessage: "Rotation root certificate PEM",
    description: "Field label for rotated workload attester root certificate PEM.",
  },
  "workloads.attestation.rotationNonce": {
    defaultMessage: "Rotation nonce (base64)",
    description: "Field label for rotated workload attester nonce.",
  },
  "workloads.attestation.rotationReason": {
    defaultMessage: "Rotation reason",
    description: "Field label for the workload attester trust rotation reason.",
  },
  "workloads.attestation.rotateTrustSource": {
    defaultMessage: "Rotate trust source",
    description: "Button label for rotating a workload attester trust source.",
  },
  "workloads.attestation.errorTitle": {
    defaultMessage: "Attester trust source failed",
    description: "Error title for workload attester trust source operations.",
  },
  "workloads.attestation.loadErrorFallback": {
    defaultMessage: "Could not load attester trust sources",
    description: "Fallback error text when workload attester trust sources cannot load.",
  },
  "workloads.attestation.createErrorFallback": {
    defaultMessage: "Could not create attester trust source",
    description: "Fallback error text when creating a workload attester trust source fails.",
  },
  "workloads.attestation.selectToRotate": {
    defaultMessage: "Select an attester trust source to rotate",
    description: "Validation error when rotation is submitted without a trust source.",
  },
  "workloads.attestation.rotateErrorFallback": {
    defaultMessage: "Could not rotate attester trust source",
    description: "Fallback error text when rotating a workload attester trust source fails.",
  },
  "workloads.attestation.revokeErrorFallback": {
    defaultMessage: "Could not revoke attester trust source",
    description: "Fallback error text when revoking a workload attester trust source fails.",
  },
  "workloads.attestation.deleteErrorFallback": {
    defaultMessage: "Could not delete attester trust source",
    description: "Fallback error text when deleting a workload attester trust source fails.",
  },
  "workloads.attestation.caption": {
    defaultMessage: "Attester trust sources",
    description: "Screen-reader caption for the workload attester trust source table.",
  },
  "workloads.attestation.nameColumn": {
    defaultMessage: "Name",
    description: "Trust-source table name column heading.",
  },
  "workloads.attestation.methodColumn": {
    defaultMessage: "Method",
    description: "Trust-source table method column heading.",
  },
  "workloads.attestation.statusColumn": {
    defaultMessage: "Status",
    description: "Trust-source table status column heading.",
  },
  "workloads.attestation.versionColumn": {
    defaultMessage: "Version",
    description: "Trust-source table version column heading.",
  },
  "workloads.attestation.lastRotatedColumn": {
    defaultMessage: "Last rotated",
    description: "Trust-source table last-rotated column heading.",
  },
  "workloads.attestation.empty": {
    defaultMessage: "No attester trust source has been configured.",
    description: "Empty-state text for the workload attester trust source table.",
  },
  "workloads.attestation.revokeButton": {
    defaultMessage: "Revoke",
    description: "Button label for revoking a workload attester trust source.",
  },
  "workloads.attestation.offboardButton": {
    defaultMessage: "Offboard",
    description: "Button label for deleting a workload attester trust source.",
  },
  "workloads.attestation.statusRevoked": {
    defaultMessage: "Revoked",
    description: "Status label for a revoked workload attester trust source.",
  },
  "workloads.attestation.statusDisabled": {
    defaultMessage: "Disabled",
    description: "Status label for a disabled workload attester trust source.",
  },
  "workloads.attestation.statusEnabled": {
    defaultMessage: "Enabled",
    description: "Status label for an enabled workload attester trust source.",
  },
  "workloads.attestation.issueHeading": {
    defaultMessage: "Issue attested SVID",
    description: "Form heading for issuing an attested SVID.",
  },
  "workloads.attestation.issueDescription": {
    defaultMessage: "Proof payloads and returned certificates are cleared instead of being stored in UI state.",
    description: "Security note for attested SVID issuance.",
  },
  "workloads.attestation.proofPayload": {
    defaultMessage: "Attestation proof payload (base64)",
    description: "Field label for the attested SVID proof payload.",
  },
  "workloads.attestation.publicKey": {
    defaultMessage: "Workload public key",
    description: "Field label for the attested SVID public key.",
  },
  "workloads.attestation.svidTTL": {
    defaultMessage: "SVID TTL seconds",
    description: "Field label for the attested SVID TTL.",
  },
  "workloads.attestation.issueButton": {
    defaultMessage: "Issue attested SVID",
    description: "Button label for issuing an attested SVID.",
  },
  "workloads.attestation.issueErrorTitle": {
    defaultMessage: "Attested SVID failed",
    description: "Error title for attested SVID issuance.",
  },
  "workloads.attestation.issueErrorFallback": {
    defaultMessage: "Could not issue attested SVID",
    description: "Fallback error text when attested SVID issuance fails.",
  },
  "workloads.attestation.outcomesCaption": {
    defaultMessage: "Attested SVID outcomes",
    description: "Screen-reader caption for attested SVID outcomes.",
  },
  "apiExplorer.title": {
    defaultMessage: "API explorer",
    description: "Page title for the runnable API explorer.",
  },
  "apiExplorer.description": {
    defaultMessage: "Select a contract operation, mint a short-lived scoped test key, run the request, and inspect the response.",
    description: "Page description for the runnable API explorer.",
  },
  "apiExplorer.back": {
    defaultMessage: "Integration hub",
    description: "Link back to the integration hub.",
  },
  "apiExplorer.loading": {
    defaultMessage: "Loading contract operations.",
    description: "Status text while the API explorer loads its contract.",
  },
  "apiExplorer.loadFailed": {
    defaultMessage: "Contract operations could not be loaded.",
    description: "Error title shown when the API explorer cannot load its contract.",
  },
  "apiExplorer.reload": {
    defaultMessage: "Reload",
    description: "Button label for reloading the API explorer contract.",
  },
  "apiExplorer.operations": {
    defaultMessage: "Operations",
    description: "Heading for API operation selector.",
  },
  "apiExplorer.searchLabel": {
    defaultMessage: "Filter operations",
    description: "Accessible label for API operation search.",
  },
  "apiExplorer.searchPlaceholder": {
    defaultMessage: "Filter by name or path",
    description: "Placeholder for API operation search.",
  },
  "apiExplorer.operationCount": {
    defaultMessage: "{count} operations",
    description: "Count of API operations.",
  },
  "apiExplorer.operationDetails": {
    defaultMessage: "Operation details",
    description: "Heading for selected API operation details.",
  },
  "apiExplorer.noMatches": {
    defaultMessage: "No operations match this filter.",
    description: "Empty state for API operation filtering.",
  },
  "apiExplorer.route": {
    defaultMessage: "Route",
    description: "Label for the selected API route.",
  },
  "apiExplorer.operationId": {
    defaultMessage: "Operation ID",
    description: "Label for the selected API operation id.",
  },
  "apiExplorer.permission": {
    defaultMessage: "Permission",
    description: "Label for selected operation permission scope.",
  },
  "apiExplorer.required": {
    defaultMessage: "required",
    description: "Badge for required API parameters.",
  },
  "apiExplorer.optional": {
    defaultMessage: "optional",
    description: "Badge for optional API parameters.",
  },
  "apiExplorer.pathParameters": {
    defaultMessage: "Path parameters",
    description: "Heading for path parameters.",
  },
  "apiExplorer.queryParameters": {
    defaultMessage: "Query parameters",
    description: "Heading for query parameters.",
  },
  "apiExplorer.noParameters": {
    defaultMessage: "This request has no required parameters.",
    description: "Empty state for API operation parameters.",
  },
  "apiExplorer.requestBody": {
    defaultMessage: "Request body",
    description: "Heading for request body sample.",
  },
  "apiExplorer.requestPreview": {
    defaultMessage: "Request preview",
    description: "Heading for runnable request preview.",
  },
  "apiExplorer.noRequestBody": {
    defaultMessage: "This request does not send a body.",
    description: "Empty state for request body sample.",
  },
  "apiExplorer.examples": {
    defaultMessage: "Examples",
    description: "Heading for generated request examples.",
  },
  "apiExplorer.copyCurl": {
    defaultMessage: "Copy curl",
    description: "Button label for copying a curl example.",
  },
  "apiExplorer.copySdk": {
    defaultMessage: "Copy SDK",
    description: "Button label for copying an SDK example.",
  },
  "apiExplorer.copied": {
    defaultMessage: "Copied",
    description: "Copy button status after clipboard write.",
  },
  "apiExplorer.runner": {
    defaultMessage: "Runnable request",
    description: "Heading for API request runner.",
  },
  "apiExplorer.subject": {
    defaultMessage: "Token subject",
    description: "Label for the test token subject input.",
  },
  "apiExplorer.tokenScope": {
    defaultMessage: "Token scope",
    description: "Label for the test token scope field.",
  },
  "apiExplorer.testKey": {
    defaultMessage: "Generate test key",
    description: "Button label for minting a scoped test API key.",
  },
  "apiExplorer.generating": {
    defaultMessage: "Generating...",
    description: "Button status while minting a scoped test key.",
  },
  "apiExplorer.keyReady": {
    defaultMessage: "Scoped test key ready for {scope}.",
    description: "Status after a test API key is minted.",
  },
  "apiExplorer.revealOnce": {
    defaultMessage: "Reveal-once value is held only in this browser session.",
    description: "Notice for a one-time API token.",
  },
  "apiExplorer.keyFailed": {
    defaultMessage: "Could not mint a scoped test key.",
    description: "Error title when test key minting fails.",
  },
  "apiExplorer.expires": {
    defaultMessage: "Expires",
    description: "Label for a test key expiry.",
  },
  "apiExplorer.run": {
    defaultMessage: "Run request",
    description: "Button label for executing the selected API request.",
  },
  "apiExplorer.running": {
    defaultMessage: "Running...",
    description: "Button status while the selected API request is running.",
  },
  "apiExplorer.needsKey": {
    defaultMessage: "Generate a scoped test key before running this request.",
    description: "Helper text when no test key is available.",
  },
  "apiExplorer.response": {
    defaultMessage: "Response",
    description: "Heading for API explorer response output.",
  },
  "apiExplorer.problemResponse": {
    defaultMessage: "Problem response",
    description: "Heading for structured problem response output.",
  },
  "apiExplorer.problemTitle": {
    defaultMessage: "Problem title",
    description: "Label for a structured problem title.",
  },
  "apiExplorer.problemDetail": {
    defaultMessage: "Problem detail",
    description: "Label for a structured problem detail.",
  },
  "apiExplorer.status": {
    defaultMessage: "Status",
    description: "Label for response status.",
  },
  "apiExplorer.contentType": {
    defaultMessage: "Content type",
    description: "Label for response content type.",
  },
  "apiExplorer.noResponse": {
    defaultMessage: "Run a request to see the response.",
    description: "Empty state for API explorer response output.",
  },
  "apiExplorer.responseBody": {
    defaultMessage: "Response body",
    description: "Heading for raw API response body output.",
  },
  "apiExplorer.runFailed": {
    defaultMessage: "Request execution failed.",
    description: "Error title when request execution fails before a response.",
  },
  "integrate.title": {
    defaultMessage: "Integrate",
    description: "Integrate route page title.",
  },
  "integrate.description": {
    defaultMessage: "Wire trstctl into your stack: enrollment protocols, language SDKs, and infrastructure-as-code, each with a copyable reference.",
    description: "Integrate route page description.",
  },
  "integrate.copy.copy": {
    defaultMessage: "Copy",
    description: "Button label for copying an integration reference.",
  },
  "integrate.copy.copied": {
    defaultMessage: "Copied",
    description: "Copied-state button label for an integration reference.",
  },
  "integrate.copy.value": {
    defaultMessage: "Copy {value}",
    description: "Accessible label for copying a specific integration reference.",
  },
  "integrate.protocols.title": {
    defaultMessage: "Enrollment protocols",
    description: "Integrate route enrollment protocol section title.",
  },
  "integrate.protocols.description": {
    defaultMessage: "Standards-based certificate enrollment endpoints (per issuance profile).",
    description: "Integrate route enrollment protocol section description.",
  },
  "integrate.sdks.title": {
    defaultMessage: "SDKs",
    description: "Integrate route SDK section title.",
  },
  "integrate.sdks.description": {
    defaultMessage: "Generated client libraries for the trstctl API.",
    description: "Integrate route SDK section description.",
  },
  "integrate.gitops.title": {
    defaultMessage: "GitOps workflow",
    description: "Integrate route GitOps workflow section title.",
  },
  "integrate.gitops.description": {
    defaultMessage: "Generate declarations from live state, validate them through policy dry-run, and compare live versus declared fields.",
    description: "Integrate route GitOps workflow section description.",
  },
  "integrate.gitops.loadUnavailable": {
    defaultMessage: "GitOps live state unavailable",
    description: "Fallback error when GitOps live state cannot be loaded.",
  },
  "integrate.gitops.manifest.profile": {
    defaultMessage: "Issuance profile",
    description: "Manifest type option for issuance profiles.",
  },
  "integrate.gitops.manifest.discoverySource": {
    defaultMessage: "Discovery source",
    description: "Manifest type option for discovery sources.",
  },
  "integrate.gitops.manifest.routingPolicy": {
    defaultMessage: "Notification routing policy",
    description: "Manifest type option for notification routing policies.",
  },
  "integrate.gitops.manifest.installValues": {
    defaultMessage: "Install values",
    description: "Manifest type option for installation values.",
  },
  "integrate.gitops.manifestType": {
    defaultMessage: "Manifest type",
    description: "Label for selecting a GitOps manifest type.",
  },
  "integrate.gitops.liveObject": {
    defaultMessage: "Live object",
    description: "Label for selecting the live object used to generate a declaration.",
  },
  "integrate.gitops.loading": {
    defaultMessage: "Loading GitOps sources...",
    description: "Loading state while GitOps live sources are fetched.",
  },
  "integrate.gitops.declarativeManifest": {
    defaultMessage: "Declarative manifest",
    description: "Label for the editable GitOps declaration textarea.",
  },
  "integrate.gitops.validateDeclaration": {
    defaultMessage: "Validate declaration",
    description: "Button label for validating a GitOps declaration.",
  },
  "integrate.gitops.validating": {
    defaultMessage: "Validating",
    description: "Busy button text while a GitOps declaration is validating.",
  },
  "integrate.gitops.copyDeclaration": {
    defaultMessage: "Copy declaration",
    description: "Button label for copying a GitOps declaration.",
  },
  "integrate.gitops.exportDeclaration": {
    defaultMessage: "Export declaration",
    description: "Link label for downloading a GitOps declaration.",
  },
  "integrate.gitops.openApiExplorer": {
    defaultMessage: "Open in API explorer",
    description: "Link label to open the GitOps policy dry run in the API explorer.",
  },
  "integrate.gitops.validationResult": {
    defaultMessage: "GitOps validation result",
    description: "Accessible label for the GitOps validation result panel.",
  },
  "integrate.gitops.valid": {
    defaultMessage: "Valid",
    description: "GitOps validation status for a valid declaration.",
  },
  "integrate.gitops.invalid": {
    defaultMessage: "Invalid",
    description: "GitOps validation status for an invalid declaration.",
  },
  "integrate.gitops.decision": {
    defaultMessage: "Decision",
    description: "GitOps validation metric label for policy decision.",
  },
  "integrate.gitops.moduleDigest": {
    defaultMessage: "Module digest",
    description: "GitOps validation metric label for module digest.",
  },
  "integrate.gitops.query": {
    defaultMessage: "Query",
    description: "GitOps validation metric label for policy query.",
  },
  "integrate.gitops.idempotency": {
    defaultMessage: "Idempotency",
    description: "GitOps validation metric label for idempotency key.",
  },
  "integrate.gitops.driftComparison": {
    defaultMessage: "GitOps drift comparison",
    description: "Accessible caption for the GitOps drift comparison table.",
  },
  "integrate.gitops.path": {
    defaultMessage: "Path",
    description: "GitOps drift table path column.",
  },
  "integrate.gitops.live": {
    defaultMessage: "Live",
    description: "GitOps drift table live-state column.",
  },
  "integrate.gitops.declared": {
    defaultMessage: "Declared",
    description: "GitOps drift table declared-state column.",
  },
  "integrate.gitops.status": {
    defaultMessage: "Status",
    description: "GitOps drift table status column.",
  },
  "integrate.gitops.noComparableDeclaration": {
    defaultMessage: "No comparable declaration loaded.",
    description: "Empty state for the GitOps drift comparison table.",
  },
  "integrate.gitops.driftSummary": {
    defaultMessage: "{count} drift {fields}",
    description: "Summary count for GitOps drift fields.",
  },
  "integrate.gitops.fieldSingular": {
    defaultMessage: "field",
    description: "Singular noun for one drift field.",
  },
  "integrate.gitops.fieldPlural": {
    defaultMessage: "fields",
    description: "Plural noun for drift fields.",
  },
  "integrate.iac.title": {
    defaultMessage: "Infrastructure as code",
    description: "Integrate route infrastructure-as-code section title.",
  },
  "integrate.iac.description": {
    defaultMessage: "Declare trstctl trust the same way you declare the rest of your platform.",
    description: "Integrate route infrastructure-as-code section description.",
  },
  "privacy.title": {
    defaultMessage: "Privacy & data governance",
    description: "Privacy route page title.",
  },
  "privacy.description": {
    defaultMessage:
      "Privacy & GDPR controls: inventory the kinds of personal data you hold, honor erasure requests (right to be forgotten), and enforce data-retention schedules.",
    description: "Privacy route page description.",
  },
  "privacy.loading": {
    defaultMessage: "Loading privacy posture...",
    description: "Privacy route loading state.",
  },
  "privacy.stats.catalogEntries": {
    defaultMessage: "Catalog entries",
    description: "Privacy summary metric for personal-data catalog entries.",
  },
  "privacy.stats.subjectErasures": {
    defaultMessage: "Subject erasures",
    description: "Privacy summary metric for subject erasure requests.",
  },
  "privacy.stats.retentionRuns": {
    defaultMessage: "Retention runs",
    description: "Privacy summary metric for retention enforcement runs.",
  },
  "privacy.error.actionFailed": {
    defaultMessage: "Privacy action failed",
    description: "Privacy route action error title.",
  },
  "privacy.erasure.title": {
    defaultMessage: "Subject erasure",
    description: "Subject erasure section title.",
  },
  "privacy.erasure.description": {
    defaultMessage: "Right to be forgotten - erase every credential and record tied to a data subject.",
    description: "Subject erasure section description.",
  },
  "privacy.erasure.subjectLabel": {
    defaultMessage: "Data subject",
    description: "Label for the subject erasure subject input.",
  },
  "privacy.subjectPlaceholder": {
    defaultMessage: "owner id, email, or subject ref",
    description: "Placeholder for privacy subject reference inputs.",
  },
  "privacy.erasure.reasonLabel": {
    defaultMessage: "Reason",
    description: "Label for subject erasure reason.",
  },
  "privacy.erasure.reasonPlaceholder": {
    defaultMessage: "optional - recorded on the erasure",
    description: "Placeholder for optional subject erasure reason.",
  },
  "privacy.erasure.busy": {
    defaultMessage: "Erasing...",
    description: "Busy text while submitting a subject erasure.",
  },
  "privacy.erasure.submit": {
    defaultMessage: "Erase subject",
    description: "Button label for submitting a subject erasure.",
  },
  "privacy.erasure.empty": {
    defaultMessage: "No subject erasures recorded yet.",
    description: "Empty state for subject erasures.",
  },
  "privacy.erasure.tableCaption": {
    defaultMessage: "Recent subject erasures",
    description: "Accessible caption for recent subject erasures table.",
  },
  "privacy.subjectColumn": {
    defaultMessage: "Subject",
    description: "Shared privacy table column for a subject.",
  },
  "privacy.erasure.recordsErasedColumn": {
    defaultMessage: "Records erased",
    description: "Subject erasure table column for records erased.",
  },
  "privacy.erasure.erasedAtColumn": {
    defaultMessage: "Erased at",
    description: "Subject erasure table column for erasure time.",
  },
  "privacy.export.title": {
    defaultMessage: "Subject export",
    description: "Subject export section title.",
  },
  "privacy.export.description": {
    defaultMessage: "Access and portability workflow for every cataloged record tied to a data subject.",
    description: "Subject export section description.",
  },
  "privacy.export.subjectLabel": {
    defaultMessage: "Export data subject",
    description: "Label for the subject export subject input.",
  },
  "privacy.export.busy": {
    defaultMessage: "Exporting...",
    description: "Busy text while exporting subject records.",
  },
  "privacy.export.submit": {
    defaultMessage: "Export subject",
    description: "Button label for submitting a subject export.",
  },
  "privacy.export.failed": {
    defaultMessage: "Subject export failed",
    description: "Subject export error title.",
  },
  "privacy.export.subjectRef": {
    defaultMessage: "Subject ref",
    description: "Subject export detail label for the canonical subject reference.",
  },
  "privacy.export.generated": {
    defaultMessage: "Generated",
    description: "Subject export detail label for generation time.",
  },
  "privacy.export.countsCaption": {
    defaultMessage: "Subject export counts",
    description: "Accessible caption for subject export counts table.",
  },
  "privacy.export.recordClassColumn": {
    defaultMessage: "Record class",
    description: "Subject export counts table record-class column.",
  },
  "privacy.export.countColumn": {
    defaultMessage: "Count",
    description: "Subject export counts table count column.",
  },
  "privacy.export.summary": {
    defaultMessage: "Exported {count} cataloged record references. Secret values and token material are not rendered.",
    description: "Subject export summary after a successful export.",
  },
  "privacy.retention.title": {
    defaultMessage: "Retention enforcement",
    description: "Retention enforcement section title.",
  },
  "privacy.retention.description": {
    defaultMessage: "Apply the retention policy across credentials, owners, agents, and evidence - each run records its cutoffs.",
    description: "Retention enforcement section description.",
  },
  "privacy.retention.busy": {
    defaultMessage: "Enforcing...",
    description: "Busy text while enforcing retention.",
  },
  "privacy.retention.submit": {
    defaultMessage: "Enforce retention now",
    description: "Button label for enforcing retention.",
  },
  "privacy.retention.empty": {
    defaultMessage: "No retention runs recorded yet.",
    description: "Empty state for retention runs.",
  },
  "privacy.retention.tableCaption": {
    defaultMessage: "Retention runs",
    description: "Accessible caption for retention runs table.",
  },
  "privacy.retention.runColumn": {
    defaultMessage: "Run",
    description: "Retention runs table run id column.",
  },
  "privacy.retention.recordsAffectedColumn": {
    defaultMessage: "Records affected",
    description: "Retention runs table records affected column.",
  },
  "privacy.retention.requestedByColumn": {
    defaultMessage: "Requested by",
    description: "Retention runs table requester column.",
  },
  "privacy.retention.enforcedAtColumn": {
    defaultMessage: "Enforced at",
    description: "Retention runs table enforcement time column.",
  },
  "privacy.catalog.title": {
    defaultMessage: "Personal-data catalog",
    description: "Personal-data catalog section title.",
  },
  "privacy.catalog.description": {
    defaultMessage: "What personal data lives where, who owns it, why it is held, and how it is erased.",
    description: "Personal-data catalog section description.",
  },
  "privacy.catalog.empty": {
    defaultMessage: "No catalog entries returned.",
    description: "Empty state for personal-data catalog.",
  },
  "privacy.catalog.categoryColumn": {
    defaultMessage: "Category",
    description: "Personal-data catalog category column.",
  },
  "privacy.catalog.locationColumn": {
    defaultMessage: "Location",
    description: "Personal-data catalog location column.",
  },
  "privacy.catalog.ownerColumn": {
    defaultMessage: "Owner",
    description: "Personal-data catalog owner column.",
  },
  "privacy.catalog.purposeColumn": {
    defaultMessage: "Purpose",
    description: "Personal-data catalog purpose column.",
  },
  "privacy.catalog.retentionColumn": {
    defaultMessage: "Retention",
    description: "Personal-data catalog retention column.",
  },
  "parity.airGap_a0134a": {
    defaultMessage: "Air gap",
    description: "CLI-parity console flow copy.",
  },
  "parity.allowWildcardIssuance_0fe53c": {
    defaultMessage: "Allow wildcard issuance",
    description: "CLI-parity console flow copy.",
  },
  "parity.allowedMethods_ac5c6c": {
    defaultMessage: "Allowed methods",
    description: "CLI-parity console flow copy.",
  },
  "parity.applyIdentityFilter_72d5ba": {
    defaultMessage: "Apply identity filter",
    description: "CLI-parity console flow copy.",
  },
  "parity.approveEphemeralCredential_760861": {
    defaultMessage: "Approve ephemeral credential",
    description: "CLI-parity console flow copy.",
  },
  "parity.approversCanIssueThisFromThe_33b073": {
    defaultMessage: "Approvers can issue this from the Approvals page.",
    description: "CLI-parity console flow copy.",
  },
  "parity.archiveAttestationRequestFailed_6179ba": {
    defaultMessage: "Archive attestation request failed",
    description: "CLI-parity console flow copy.",
  },
  "parity.archiveErasureAttestationRecorded_4e1490": {
    defaultMessage: "Archive erasure attestation recorded",
    description: "CLI-parity console flow copy.",
  },
  "parity.archiveErasureEvidence_9a62ca": {
    defaultMessage: "Archive erasure evidence",
    description: "CLI-parity console flow copy.",
  },
  "parity.artifactUri_2088cf": {
    defaultMessage: "Artifact URI",
    description: "CLI-parity console flow copy.",
  },
  "parity.attestationGatedCredentials_2887bd": {
    defaultMessage: "Attestation-gated credentials",
    description: "CLI-parity console flow copy.",
  },
  "parity.attestationPayloadBase64_b7cf3a": {
    defaultMessage: "Attestation payload (base64)",
    description: "CLI-parity console flow copy.",
  },
  "parity.backup_89121d": {
    defaultMessage: "backup",
    description: "CLI-parity console flow copy.",
  },
  "parity.brokerEvidenceForThisJustIn_44ca48": {
    defaultMessage: "Broker evidence for this just-in-time access session, including attestation and audit records.",
    description: "CLI-parity console flow copy.",
  },
  "parity.builtInGuarantees_21db16": {
    defaultMessage: "Built-in guarantees",
    description: "CLI-parity console flow copy.",
  },
  "parity.caaIssuerDomainOptional_8c2f53": {
    defaultMessage: "CAA issuer domain (optional)",
    description: "CLI-parity console flow copy.",
  },
  "parity.captureEvidenceOfHowABackup_f00d4e": {
    defaultMessage: "Capture evidence of how a backup or signed audit archive honored a subject erasure.",
    description: "CLI-parity console flow copy.",
  },
  "parity.ceremonyDetail_9cb326": {
    defaultMessage: "Ceremony detail",
    description: "CLI-parity console flow copy.",
  },
  "parity.ceremonyId_6f8ee6": {
    defaultMessage: "Ceremony ID",
    description: "CLI-parity console flow copy.",
  },
  "parity.certifiesAnExternallyHeldIntermediateKey_d95cc4": {
    defaultMessage: "Certifies an externally held intermediate key under this authority via a quorum-approved ceremony.",
    description: "CLI-parity console flow copy.",
  },
  "parity.challengeDomainOptional_d7bed2": {
    defaultMessage: "Challenge domain (optional)",
    description: "CLI-parity console flow copy.",
  },
  "parity.challengeMode_1c8fbd": {
    defaultMessage: "Challenge mode",
    description: "CLI-parity console flow copy.",
  },
  "parity.challengeRecord_320513": {
    defaultMessage: "Challenge record",
    description: "CLI-parity console flow copy.",
  },
  "parity.challengeRotationFailed_c4b11e": {
    defaultMessage: "Challenge rotation failed",
    description: "CLI-parity console flow copy.",
  },
  "parity.clearIdentityFilter_3c0b9a": {
    defaultMessage: "Clear identity filter",
    description: "CLI-parity console flow copy.",
  },
  "parity.closeAuthorityDetail_9bee0e": {
    defaultMessage: "Close authority detail",
    description: "CLI-parity console flow copy.",
  },
  "parity.closeCeremonyDetail_92fb97": {
    defaultMessage: "Close ceremony detail",
    description: "CLI-parity console flow copy.",
  },
  "parity.closeCreateCaForm_e01a8e": {
    defaultMessage: "Close create CA form",
    description: "CLI-parity console flow copy.",
  },
  "parity.closeDns01ConfigForm_00c6cb": {
    defaultMessage: "Close DNS-01 config form",
    description: "CLI-parity console flow copy.",
  },
  "parity.closeIssueLeafForm_2c9eeb": {
    defaultMessage: "Close issue leaf form",
    description: "CLI-parity console flow copy.",
  },
  "parity.closePreflightDialog_97a0fb": {
    defaultMessage: "Close preflight dialog",
    description: "CLI-parity console flow copy.",
  },
  "parity.closeScepPolicyForm_ae9570": {
    defaultMessage: "Close SCEP policy form",
    description: "CLI-parity console flow copy.",
  },
  "parity.closeSignIntermediateCsrForm_162507": {
    defaultMessage: "Close sign intermediate CSR form",
    description: "CLI-parity console flow copy.",
  },
  "parity.commonNameMaxPathLenSignature_0d8b25": {
    defaultMessage: "common_name, max_path_len, signature_algorithm, ttl_seconds",
    description: "CLI-parity console flow copy.",
  },
  "parity.configName_11f179": {
    defaultMessage: "Config name",
    description: "CLI-parity console flow copy.",
  },
  "parity.controlPlaneLineage_513399": {
    defaultMessage: "Control-plane lineage",
    description: "CLI-parity console flow copy.",
  },
  "parity.copied_dd2ce2": {
    defaultMessage: "Copied.",
    description: "CLI-parity console flow copy.",
  },
  "parity.copyCertificate_59db8a": {
    defaultMessage: "Copy certificate",
    description: "CLI-parity console flow copy.",
  },
  "parity.copyRequestId_a53908": {
    defaultMessage: "Copy request ID",
    description: "CLI-parity console flow copy.",
  },
  "parity.couldNotRecordAttestation_204858": {
    defaultMessage: "Could not record attestation",
    description: "CLI-parity console flow copy.",
  },
  "parity.createIntermediateCa_829ab7": {
    defaultMessage: "Create intermediate CA",
    description: "CLI-parity console flow copy.",
  },
  "parity.createRootCa_94fb33": {
    defaultMessage: "Create root CA",
    description: "CLI-parity console flow copy.",
  },
  "parity.createRotationSchedule_6a80bd": {
    defaultMessage: "Create rotation schedule",
    description: "CLI-parity console flow copy.",
  },
  "parity.credentialReferencesJsonOptional_faddae": {
    defaultMessage: "Credential references JSON (optional)",
    description: "CLI-parity console flow copy.",
  },
  "parity.cryptoAgilityMeansTheSystemCan_20c325": {
    defaultMessage:
      "Crypto-agility means the system can see weak algorithms, reject disallowed choices, and plan safe rotations without guessing from browser-only state.",
    description: "CLI-parity console flow copy.",
  },
  "parity.cryptographicShred_caafb7": {
    defaultMessage: "cryptographic shred",
    description: "CLI-parity console flow copy.",
  },
  "parity.csrPem_c5931f": {
    defaultMessage: "CSR PEM",
    description: "CLI-parity console flow copy.",
  },
  "parity.delegationTargetOptional_8439dd": {
    defaultMessage: "Delegation target (optional)",
    description: "CLI-parity console flow copy.",
  },
  "parity.deleteOwner_b5f9bd": {
    defaultMessage: "Delete owner",
    description: "CLI-parity console flow copy.",
  },
  "parity.delete_f6fdbe": {
    defaultMessage: "Delete",
    description: "CLI-parity console flow copy.",
  },
  "parity.deleted_b639f5": {
    defaultMessage: "deleted",
    description: "CLI-parity console flow copy.",
  },
  "parity.deletingAnOwnerRemovesTheAccountability_cdfad5": {
    defaultMessage: "Deleting an owner removes the accountability record for its credentials. This cannot be undone.",
    description: "CLI-parity console flow copy.",
  },
  "parity.details_dc3dec": {
    defaultMessage: "Details",
    description: "CLI-parity console flow copy.",
  },
  "parity.distributionPosture_10c8b4": {
    defaultMessage: "Distribution posture",
    description: "CLI-parity console flow copy.",
  },
  "parity.dns01ConfigUpdateFailed_86ad97": {
    defaultMessage: "DNS-01 config update failed",
    description: "CLI-parity console flow copy.",
  },
  "parity.dns01ProviderConfigDeleted_9ead6a": {
    defaultMessage: "DNS-01 provider config deleted",
    description: "CLI-parity console flow copy.",
  },
  "parity.dns01ProviderConfigUpdated_5a6d3d": {
    defaultMessage: "DNS-01 provider config updated",
    description: "CLI-parity console flow copy.",
  },
  "parity.domain_9b1091": {
    defaultMessage: "Domain",
    description: "CLI-parity console flow copy.",
  },
  "parity.editConnectorTarget_6063fb": {
    defaultMessage: "Edit connector target",
    description: "CLI-parity console flow copy.",
  },
  "parity.edit_530164": {
    defaultMessage: "Edit",
    description: "CLI-parity console flow copy.",
  },
  "parity.emailOptional_5c10b5": {
    defaultMessage: "Email (optional)",
    description: "CLI-parity console flow copy.",
  },
  "parity.ephemeralCredentialApprovals_9a4b68": {
    defaultMessage: "Ephemeral credential approvals",
    description: "CLI-parity console flow copy.",
  },
  "parity.ephemeralCredentialRequestFailed_12be63": {
    defaultMessage: "Ephemeral credential request failed",
    description: "CLI-parity console flow copy.",
  },
  "parity.eventSourcedRemediationRunEvidenceIncluding_cec725": {
    defaultMessage: "Event-sourced remediation run evidence, including the connector delivery receipt when one was recorded.",
    description: "CLI-parity console flow copy.",
  },
  "parity.evidenceReferencesOnePerLine_2bb536": {
    defaultMessage: "Evidence references (one per line)",
    description: "CLI-parity console flow copy.",
  },
  "parity.expectedAudienceOptional_51c8b7": {
    defaultMessage: "Expected audience (optional)",
    description: "CLI-parity console flow copy.",
  },
  "parity.expectedTxtValueOptional_c4e94f": {
    defaultMessage: "Expected TXT value (optional)",
    description: "CLI-parity console flow copy.",
  },
  "parity.failedPhase_49b14a": {
    defaultMessage: "Failed phase:",
    description: "CLI-parity console flow copy.",
  },
  "parity.failures_3eec15": {
    defaultMessage: "Failures",
    description: "CLI-parity console flow copy.",
  },
  "parity.filterRotationRuns_e652a6": {
    defaultMessage: "Filter rotation runs",
    description: "CLI-parity console flow copy.",
  },
  "parity.fingerprintOptional_b6cd87": {
    defaultMessage: "Fingerprint (optional)",
    description: "CLI-parity console flow copy.",
  },
  "parity.firstRunOptional_7ecf76": {
    defaultMessage: "First run (optional)",
    description: "CLI-parity console flow copy.",
  },
  "parity.fullConnectorDeliveryReceiptEvidenceIncluding_080df5": {
    defaultMessage: "Full connector delivery receipt evidence, including rollback reference and failure reason.",
    description: "CLI-parity console flow copy.",
  },
  "parity.fullLifecycleRotationRunRecordIncluding_02687f": {
    defaultMessage: "Full lifecycle rotation run record, including fingerprints, rollback reference, and error evidence.",
    description: "CLI-parity console flow copy.",
  },
  "parity.heldUntil_8cc7d7": {
    defaultMessage: "Held until",
    description: "CLI-parity console flow copy.",
  },
  "parity.hmacDynamic_cb11c5": {
    defaultMessage: "hmac-dynamic",
    description: "CLI-parity console flow copy.",
  },
  "parity.iUnderstandThisRevocationCannotBe_92d164": {
    defaultMessage: "I understand this revocation cannot be undone.",
    description: "CLI-parity console flow copy.",
  },
  "parity.identityIdFilter_48db11": {
    defaultMessage: "Identity ID filter",
    description: "CLI-parity console flow copy.",
  },
  "parity.identityUuid_209e1d": {
    defaultMessage: "identity UUID",
    description: "CLI-parity console flow copy.",
  },
  "parity.intermediateCsrSigningFailed_636cae": {
    defaultMessage: "Intermediate CSR signing failed",
    description: "CLI-parity console flow copy.",
  },
  "parity.intuneJws_b47f57": {
    defaultMessage: "intune-jws",
    description: "CLI-parity console flow copy.",
  },
  "parity.intune_2c4886": {
    defaultMessage: "intune",
    description: "CLI-parity console flow copy.",
  },
  "parity.issueLeafCertificate_bddf5d": {
    defaultMessage: "Issue leaf certificate",
    description: "CLI-parity console flow copy.",
  },
  "parity.issueLeaf_f1c3ee": {
    defaultMessage: "Issue leaf…",
    description: "CLI-parity console flow copy.",
  },
  "parity.jamf_489375": {
    defaultMessage: "jamf",
    description: "CLI-parity console flow copy.",
  },
  "parity.justInTimeOperatorSessionsBrokered_df233f": {
    defaultMessage: "Just-in-time operator sessions brokered for PostgreSQL roles and SSH principals.",
    description: "CLI-parity console flow copy.",
  },
  "parity.lastError_5e4df8": {
    defaultMessage: "Last error",
    description: "CLI-parity console flow copy.",
  },
  "parity.latestDueRotationRuns_ac4710": {
    defaultMessage: "Latest due rotation runs",
    description: "CLI-parity console flow copy.",
  },
  "parity.leafIssuanceFailed_235d03": {
    defaultMessage: "Leaf issuance failed",
    description: "CLI-parity console flow copy.",
  },
  "parity.legalHold_644327": {
    defaultMessage: "legal hold",
    description: "CLI-parity console flow copy.",
  },
  "parity.lifecycleRotationEvidenceWhoRotatedWhat_10ed9a": {
    defaultMessage: "Lifecycle rotation evidence: who rotated what, when, and how it ended.",
    description: "CLI-parity console flow copy.",
  },
  "parity.methodOverrideOptional_154ad0": {
    defaultMessage: "Method override (optional)",
    description: "CLI-parity console flow copy.",
  },
  "parity.newRotationSchedule_0d2b93": {
    defaultMessage: "New rotation schedule",
    description: "CLI-parity console flow copy.",
  },
  "parity.newSchedule_729465": {
    defaultMessage: "New schedule…",
    description: "CLI-parity console flow copy.",
  },
  "parity.noOutboxCircuitBreakers_b8a7be": {
    defaultMessage: "No outbox circuit breakers",
    description: "CLI-parity console flow copy.",
  },
  "parity.noOutboxDestinationHasRecordedCircuit_1c248f": {
    defaultMessage: "No outbox destination has recorded circuit state yet.",
    description: "CLI-parity console flow copy.",
  },
  "parity.noOwnerRemediationActionsAreQueued_596b9b": {
    defaultMessage: "No owner remediation actions are queued.",
    description: "CLI-parity console flow copy.",
  },
  "parity.observedTxtRecordsOptionalOnePer_9b6c49": {
    defaultMessage: "Observed TXT records (optional, one per line)",
    description: "CLI-parity console flow copy.",
  },
  "parity.oldReference_69d1f6": {
    defaultMessage: "Old reference",
    description: "CLI-parity console flow copy.",
  },
  "parity.openPrivilegedSession_78a445": {
    defaultMessage: "Open privileged session",
    description: "CLI-parity console flow copy.",
  },
  "parity.openSession_73b3ca": {
    defaultMessage: "Open session…",
    description: "CLI-parity console flow copy.",
  },
  "parity.openUntil_5c3e00": {
    defaultMessage: "Open until",
    description: "CLI-parity console flow copy.",
  },
  "parity.optionalEGS3Backups2026_891da1": {
    defaultMessage: "optional, e.g. s3://backups/2026-06-30.tar.zst",
    description: "CLI-parity console flow copy.",
  },
  "parity.outboxCircuitBreakers_278ec6": {
    defaultMessage: "Outbox circuit breakers",
    description: "CLI-parity console flow copy.",
  },
  "parity.ownerDeleted_079d61": {
    defaultMessage: "Owner deleted",
    description: "CLI-parity console flow copy.",
  },
  "parity.ownerRemediationQueue_610e16": {
    defaultMessage: "Owner remediation queue",
    description: "CLI-parity console flow copy.",
  },
  "parity.ownerUpdated_07b92f": {
    defaultMessage: "Owner updated",
    description: "CLI-parity console flow copy.",
  },
  "parity.ownership_3e90e4": {
    defaultMessage: "Ownership",
    description: "CLI-parity console flow copy.",
  },
  "parity.parentAuthority_d9bb89": {
    defaultMessage: "Parent authority",
    description: "CLI-parity console flow copy.",
  },
  "parity.parseError_387dc4": {
    defaultMessage: "parse error",
    description: "CLI-parity console flow copy.",
  },
  "parity.payloadBase64_738cc4": {
    defaultMessage: "Payload (base64)",
    description: "CLI-parity console flow copy.",
  },
  "parity.paymentsDbMonthly_b690bc": {
    defaultMessage: "payments-db-monthly",
    description: "CLI-parity console flow copy.",
  },
  "parity.paymentsDbPassword_50e8d6": {
    defaultMessage: "payments/db/password",
    description: "CLI-parity console flow copy.",
  },
  "parity.playbookRunHistoryUnavailable_8452d8": {
    defaultMessage: "Playbook run history unavailable",
    description: "CLI-parity console flow copy.",
  },
  "parity.playbookRuns_da379d": {
    defaultMessage: "Playbook runs",
    description: "CLI-parity console flow copy.",
  },
  "parity.policyDefault_38146c": {
    defaultMessage: "Policy default",
    description: "CLI-parity console flow copy.",
  },
  "parity.policyName_101bf6": {
    defaultMessage: "Policy name",
    description: "CLI-parity console flow copy.",
  },
  "parity.postgres_afc848": {
    defaultMessage: "postgres",
    description: "CLI-parity console flow copy.",
  },
  "parity.postgresql_519968": {
    defaultMessage: "postgresql",
    description: "CLI-parity console flow copy.",
  },
  "parity.preflightCheck_4a464a": {
    defaultMessage: "Preflight check…",
    description: "CLI-parity console flow copy.",
  },
  "parity.preflightRequestFailed_69f031": {
    defaultMessage: "Preflight request failed",
    description: "CLI-parity console flow copy.",
  },
  "parity.privilegedAccessSessions_368da5": {
    defaultMessage: "Privileged access sessions",
    description: "CLI-parity console flow copy.",
  },
  "parity.productionMode_1737a4": {
    defaultMessage: "Production mode",
    description: "CLI-parity console flow copy.",
  },
  "parity.profileGuidanceJsonOptional_fd4738": {
    defaultMessage: "Profile guidance JSON (optional)",
    description: "CLI-parity console flow copy.",
  },
  "parity.providerConfigJsonOptional_02753c": {
    defaultMessage: "Provider config JSON (optional)",
    description: "CLI-parity console flow copy.",
  },
  "parity.providerDefault_f75bf4": {
    defaultMessage: "Provider default",
    description: "CLI-parity console flow copy.",
  },
  "parity.publicKeyPem_10749e": {
    defaultMessage: "Public key (PEM)",
    description: "CLI-parity console flow copy.",
  },
  "parity.quorumApprovedCeremonyId_df8e12": {
    defaultMessage: "quorum-approved ceremony id",
    description: "CLI-parity console flow copy.",
  },
  "parity.recordedPlaybookRunsWithTheirConnector_bffffe": {
    defaultMessage: "Recorded playbook runs with their connector delivery receipts, and the owner remediation queue snapshot.",
    description: "CLI-parity console flow copy.",
  },
  "parity.recurringRollbackSafeRotationsRunBy_06c343": {
    defaultMessage: "Recurring rollback-safe rotations run by the scheduler. Run due now executes every enabled schedule whose next run is already due.",
    description: "CLI-parity console flow copy.",
  },
  "parity.remediationEvidence_5174c6": {
    defaultMessage: "Remediation evidence",
    description: "CLI-parity console flow copy.",
  },
  "parity.remoteKeyOptional_b6dff8": {
    defaultMessage: "Remote key (optional)",
    description: "CLI-parity console flow copy.",
  },
  "parity.req7c2f9a_03dd4e": {
    defaultMessage: "req-7c2f9a",
    description: "CLI-parity console flow copy.",
  },
  "parity.requestAttestationGatedEphemeralCredential_4ce3ce": {
    defaultMessage: "Request attestation-gated ephemeral credential",
    description: "CLI-parity console flow copy.",
  },
  "parity.requestId_63aa59": {
    defaultMessage: "Request ID",
    description: "CLI-parity console flow copy.",
  },
  "parity.revokeCertificate_338ad7": {
    defaultMessage: "Revoke certificate",
    description: "CLI-parity console flow copy.",
  },
  "parity.rollbackSafeRotationFailed_5f1a57": {
    defaultMessage: "Rollback-safe rotation failed",
    description: "CLI-parity console flow copy.",
  },
  "parity.rollbackSafeRotation_267d4a": {
    defaultMessage: "Rollback-safe rotation",
    description: "CLI-parity console flow copy.",
  },
  "parity.rotateAProviderBackedCredentialBy_ec7a8f": {
    defaultMessage:
      "Rotate a provider-backed credential by reference. If a phase fails, the run rolls back to the old reference and the result below reports the exact outcome. No secret values pass through this form.",
    description: "CLI-parity console flow copy.",
  },
  "parity.rotateChallenge_99fc02": {
    defaultMessage: "Rotate challenge",
    description: "CLI-parity console flow copy.",
  },
  "parity.rotationMintsFreshChallengeMaterialAnd_0aec47": {
    defaultMessage:
      "Rotation mints fresh challenge material and records rotation evidence — the rotation version increments and the rotation timestamp is persisted for audit. Profiles distributing the previous challenge stop validating for new enrollments.",
    description: "CLI-parity console flow copy.",
  },
  "parity.rotationRuns_5ec15c": {
    defaultMessage: "Rotation runs",
    description: "CLI-parity console flow copy.",
  },
  "parity.routing_7d15dd": {
    defaultMessage: "Routing",
    description: "CLI-parity console flow copy.",
  },
  "parity.runDueRotationsFailed_b9c511": {
    defaultMessage: "Run due rotations failed",
    description: "CLI-parity console flow copy.",
  },
  "parity.runModes_6fced8": {
    defaultMessage: "Run modes",
    description: "CLI-parity console flow copy.",
  },
  "parity.runRollbackSafeRotation_5a7f2d": {
    defaultMessage: "Run rollback-safe rotation",
    description: "CLI-parity console flow copy.",
  },
  "parity.saveConfig_64e1de": {
    defaultMessage: "Save config",
    description: "CLI-parity console flow copy.",
  },
  "parity.saveOwner_b67638": {
    defaultMessage: "Save owner",
    description: "CLI-parity console flow copy.",
  },
  "parity.savePolicy_77d67c": {
    defaultMessage: "Save policy",
    description: "CLI-parity console flow copy.",
  },
  "parity.saveTarget_fa5df1": {
    defaultMessage: "Save target",
    description: "CLI-parity console flow copy.",
  },
  "parity.scepChallengeRotated_77c4f1": {
    defaultMessage: "SCEP challenge rotated",
    description: "CLI-parity console flow copy.",
  },
  "parity.scepEndpoint_f4bb21": {
    defaultMessage: "SCEP endpoint",
    description: "CLI-parity console flow copy.",
  },
  "parity.scepPolicyDeleted_45064c": {
    defaultMessage: "SCEP policy deleted",
    description: "CLI-parity console flow copy.",
  },
  "parity.scepPolicyUpdateFailed_f92dc7": {
    defaultMessage: "SCEP policy update failed",
    description: "CLI-parity console flow copy.",
  },
  "parity.scepPolicyUpdated_3a2953": {
    defaultMessage: "SCEP policy updated",
    description: "CLI-parity console flow copy.",
  },
  "parity.scepProfile_315862": {
    defaultMessage: "SCEP profile",
    description: "CLI-parity console flow copy.",
  },
  "parity.scheduleName_fb63dc": {
    defaultMessage: "Schedule name",
    description: "CLI-parity console flow copy.",
  },
  "parity.scheduledRotations_1a0452": {
    defaultMessage: "Scheduled rotations",
    description: "CLI-parity console flow copy.",
  },
  "parity.secretReferencesOnlyRawCredentialsAre_f74f29": {
    defaultMessage: "Secret references only — raw credentials are never stored on the config.",
    description: "CLI-parity console flow copy.",
  },
  "parity.selectParentAuthority_76a0a6": {
    defaultMessage: "Select parent authority",
    description: "CLI-parity console flow copy.",
  },
  "parity.selectedMethod_9ad9ca": {
    defaultMessage: "Selected method",
    description: "CLI-parity console flow copy.",
  },
  "parity.serialOptional_e59169": {
    defaultMessage: "Serial (optional)",
    description: "CLI-parity console flow copy.",
  },
  "parity.servedAuthorities_52df47": {
    defaultMessage: "Available authorities",
    description: "CLI-parity console flow copy.",
  },
  "parity.sessionOpened_368838": {
    defaultMessage: "Session opened.",
    description: "CLI-parity console flow copy.",
  },
  "parity.signIntermediateCsr_cf1361": {
    defaultMessage: "Sign intermediate CSR…",
    description: "CLI-parity console flow copy.",
  },
  "parity.signIntermediateCsr_e1f90b": {
    defaultMessage: "Sign intermediate CSR",
    description: "CLI-parity console flow copy.",
  },
  "parity.signedAuditArchive_753384": {
    defaultMessage: "signed audit archive",
    description: "CLI-parity console flow copy.",
  },
  "parity.signerBackedRootsAndIntermediatesThis_957f38": {
    defaultMessage:
      "Signer-backed roots and intermediates this control plane serves. Open a row for the certificate PEM, issue a leaf from an authority, or sign an externally generated intermediate CSR.",
    description: "CLI-parity console flow copy.",
  },
  "parity.specJson_e57c5c": {
    defaultMessage: "Spec JSON",
    description: "CLI-parity console flow copy.",
  },
  "parity.sshPrincipal_8d0a6c": {
    defaultMessage: "SSH principal",
    description: "CLI-parity console flow copy.",
  },
  "parity.ssh_e8b9f6": {
    defaultMessage: "ssh",
    description: "CLI-parity console flow copy.",
  },
  "parity.subjectFilter_ae9f99": {
    defaultMessage: "Subject filter",
    description: "CLI-parity console flow copy.",
  },
  "parity.supportedHostArchives_38c6c0": {
    defaultMessage: "Supported host archives",
    description: "CLI-parity console flow copy.",
  },
  "parity.syncTargetOptional_189fc7": {
    defaultMessage: "Sync target (optional)",
    description: "CLI-parity console flow copy.",
  },
  "parity.targetConfigJson_68839a": {
    defaultMessage: "Target config JSON",
    description: "CLI-parity console flow copy.",
  },
  "parity.targetConnector_99a265": {
    defaultMessage: "Target connector",
    description: "CLI-parity console flow copy.",
  },
  "parity.targetId_00960a": {
    defaultMessage: "Target ID",
    description: "CLI-parity console flow copy.",
  },
  "parity.targetName_f2f724": {
    defaultMessage: "Target name",
    description: "CLI-parity console flow copy.",
  },
  "parity.targetType_a45f80": {
    defaultMessage: "Target type",
    description: "CLI-parity console flow copy.",
  },
  "parity.theCbomScannerInventoriesAlgorithmsKey_777219": {
    defaultMessage:
      "The CBOM scanner inventories algorithms, key sizes, TLS versions, and weak crypto posture. The policy floor is RSA-2048, EC-256, and TLS 1.2, while 3DES/DES/RC4/NULL/EXPORT/MD5 are banned.",
    description: "CLI-parity console flow copy.",
  },
  "parity.theProviderWasRolledBackCleanly_3c888a": {
    defaultMessage: "The provider was rolled back cleanly to",
    description: "CLI-parity console flow copy.",
  },
  "parity.theServedContractRequiresASpec_bf854f": {
    defaultMessage: "Intermediate issuance requires a spec (common_name, path length, TTL).",
    description: "CLI-parity console flow copy.",
  },
  "parity.tpmQuote_f72300": {
    defaultMessage: "tpm-quote",
    description: "CLI-parity console flow copy.",
  },
  "parity.trustAnchorReferencesJsonOptional_f5ea80": {
    defaultMessage: "Trust anchor references JSON (optional)",
    description: "CLI-parity console flow copy.",
  },
  "parity.ttlSecondsOptional_68f1c5": {
    defaultMessage: "TTL seconds (optional)",
    description: "CLI-parity console flow copy.",
  },
  "parity.typeConfigNameToConfirm_f46ed6": {
    defaultMessage: "Type config name to confirm",
    description: "CLI-parity console flow copy.",
  },
  "parity.typePolicyNameToConfirm_fc5738": {
    defaultMessage: "Type policy name to confirm",
    description: "CLI-parity console flow copy.",
  },
  "parity.typeTargetNameToConfirm_aedaad": {
    defaultMessage: "Type target name to confirm",
    description: "CLI-parity console flow copy.",
  },
  "parity.typeTheExactOwnerName_1205b0": {
    defaultMessage: "Type the exact owner name",
    description: "CLI-parity console flow copy.",
  },
  "parity.updateTheConnectorTargetNameConnector_1dafe2": {
    defaultMessage: "Update the connector target name, connector, and config JSON, then save to apply the change.",
    description: "CLI-parity console flow copy.",
  },
  "parity.validatesDelegationTxtPropagationCaaPolicy_1ceb4c": {
    defaultMessage: "Validates delegation, TXT propagation, CAA policy, and challenge-method selection for a domain before an ACME order is placed.",
    description: "CLI-parity console flow copy.",
  },
  "parity.view_69bd4e": {
    defaultMessage: "View",
    description: "CLI-parity console flow copy.",
  },
  "parity.wildcard_08654e": {
    defaultMessage: "wildcard",
    description: "CLI-parity console flow copy.",
  },
  "parity.yesDeleteConfig_bd6fac": {
    defaultMessage: "Yes, delete config",
    description: "CLI-parity console flow copy.",
  },
  "parity.yesDeletePolicy_30ce34": {
    defaultMessage: "Yes, delete policy",
    description: "CLI-parity console flow copy.",
  },
  "parity.yesDeleteTarget_729269": {
    defaultMessage: "Yes, delete target",
    description: "CLI-parity console flow copy.",
  },
  "parity.zoneOptional_0f915d": {
    defaultMessage: "Zone (optional)",
    description: "CLI-parity console flow copy.",
  },
} as const;

export type MessageKey = keyof typeof messages;

export const localeLabelKeys = {
  "en-US": "locale.enUS",
  "es-ES": "locale.esES",
  "en-XA": "locale.enXA",
  "ar-XB": "locale.arXB",
} satisfies Record<Locale, MessageKey>;

export function isSupportedLocale(value: string): value is Locale {
  return (supportedLocales as readonly string[]).includes(value);
}

export function interpolateMessage(message: string, values: MessageValues = {}): string {
  return message.replace(/\{([a-zA-Z0-9_]+)\}/g, (match, name: string) => {
    const value = values[name];
    return value == null ? match : String(value);
  });
}

export function pseudoLocalize(message: string): string {
  const map: Record<string, string> = {
    A: "Å",
    B: "Ɓ",
    C: "Ç",
    D: "Ð",
    E: "É",
    F: "Ƒ",
    G: "Ĝ",
    H: "Ħ",
    I: "Ī",
    J: "Ĵ",
    K: "Ķ",
    L: "Ļ",
    M: "Ṁ",
    N: "Ñ",
    O: "Ø",
    P: "Ƥ",
    Q: "Ǫ",
    R: "Ř",
    S: "Ş",
    T: "Ŧ",
    U: "Ů",
    V: "Ṽ",
    W: "Ŵ",
    X: "Ẋ",
    Y: "Ý",
    Z: "Ž",
    a: "å",
    b: "ƀ",
    c: "ç",
    d: "ď",
    e: "é",
    f: "ƒ",
    g: "ĝ",
    h: "ħ",
    i: "ī",
    j: "ĵ",
    k: "ķ",
    l: "ļ",
    m: "ṁ",
    n: "ñ",
    o: "ø",
    p: "ƥ",
    q: "ǫ",
    r: "ř",
    s: "ş",
    t: "ŧ",
    u: "ů",
    v: "ṽ",
    w: "ŵ",
    x: "ẋ",
    y: "ý",
    z: "ž",
  };
  return `[${message.replace(/[A-Za-z]/g, (char) => map[char] ?? char)}]`;
}

const esESCatalog = {
  "app.loading": "Cargando...",
  "app.brand.name": "trstctl",
  "app.brand.subtitle": "plano de control",
  "app.skipToMain": "Saltar al contenido principal",
  "credentialChip.copy": "Copiar {label}",
  "credentialChip.copied": "Copiado al portapapeles",
  "graph.view.zoomIn": "Acercar",
  "graph.view.zoomOut": "Alejar",
  "graph.view.resetView": "Restablecer vista",
  "graph.explorer.delegatedHint": "Los resultados se pintan en el mapa inferior y se detallan en el panel de análisis.",
  "certificates.tabs.inventory": "Inventario",
  "certificates.tabs.health": "Salud del entorno",
  "certificates.tabs.crlct": "CRL y CT",
  "certificates.tabs.renewal": "Preparación de renovación",
  "certificates.ct.launch": "Enviar a CT",
  "certificates.ct.launchDescription": "Ponga en cola certificados firmados para su envío a los registros de Certificate Transparency.",
  "secrets.tabs.store": "Almacén",
  "secrets.tabs.access": "Acceso",
  "secrets.tabs.sharing": "Compartir",
  "secrets.tabs.engines": "Motores",
  "secrets.tabs.scanning": "Escaneo CI",
  "secrets.tabs.sync": "Sincronización",
  "discovery.tabs.findings": "Hallazgos",
  "discovery.tabs.sources": "Fuentes",
  "discovery.tabs.schedules": "Programaciones",
  "discovery.tabs.runs": "Ejecuciones",
  "platform.tabs.access": "Administración de acceso",
  "platform.tabs.posture": "Postura del sistema",
  "identities.decommission.heading": "Retirada por señal",
  "request.wizard.profile.label": "Elegir perfil",
  "request.wizard.profile.description": "El perfil de emisión determina el tipo de clave, la vigencia y cuántas aprobaciones necesita la solicitud.",
  "request.wizard.details.label": "Nombrar la credencial",
  "request.wizard.details.description": "Los aprobadores ven exactamente esto: cómo se llama la credencial, quién la posee y por qué existe.",
  "request.wizard.review.label": "Revisar y enviar",
  "request.wizard.review.description": "Solicitar y aprobar siguen siendo pasos separados: no se emite nada hasta que un aprobador lo autorice.",
  "request.wizard.nextDetails": "Siguiente: nombrarla",
  "wizard.protocols.stepLabel": "Habilitar protocolos",
  "wizard.protocols.stepDescription":
    "Active el perfil de evaluación vinculado al inquilino para que los clientes de inscripción estándar alcancen todos los protocolos publicados.",
  "wizard.protocols.heading": "Habilitar protocolos de inscripción",
  "wizard.protocols.description":
    "El perfil de evaluación prepara ACME, EST, SCEP, CMP, SSH, TSA y SPIFFE para este inquilino. Al activarlo, el servidor registra estado duradero antes de abrir cualquier respondedor; no es un interruptor solo del navegador.",
  "wizard.protocols.loading": "Leyendo el estado de los protocolos...",
  "wizard.protocols.responders": "Respondedores publicados: {protocols}.",
  "wizard.protocols.active": "El perfil de protocolos de evaluación está activo para este inquilino.",
  "wizard.protocols.activate": "Activar el perfil de protocolos de evaluación",
  "wizard.protocols.unavailable":
    "Este despliegue no seleccionó el perfil de evaluación. La exposición de protocolos sigue bajo la configuración explícita del operador, así que la preparación puede continuar sin cambiarla.",
  "wizard.protocols.retry": "Reintentar el estado de protocolos",
  "wizard.protocols.statusError": "No se pudo leer el estado de preparación de protocolos: {error}",
  "wizard.protocols.activationError": "No se pudo activar el perfil de protocolos de evaluación: {error}",
  "wizard.protocols.inactiveError": "el servidor devolvió un perfil inactivo",
  "wizard.protocols.summaryActive": "Perfil de evaluación activo",
  "wizard.protocols.summaryOperator": "Perfil configurado por el operador",
  "wizard.protocols.next": "Siguiente: habilitar protocolos",
  "wizard.header.description":
    "Conecte un emisor, habilite los protocolos de inscripción, emita un certificado, verifique las integraciones configuradas, inscriba un agente y termine.",
  "wizard.integrations.stepLabel": "Probar integraciones",
  "wizard.integrations.stepDescription": "Ejecute operaciones de conectores, CA ascendentes y secretos dinámicos contra los sistemas configurados.",
  "wizard.integrations.heading": "Verificar integraciones configuradas",
  "wizard.integrations.description":
    "Estas comprobaciones usan las mismas rutas del producto que la automatización diaria. Requieren sistemas configurados por un operador; puede omitir esta prueba opcional en una instalación solo con el núcleo.",
  "wizard.integrations.loading": "Cargando catálogos de integraciones...",
  "wizard.integrations.connector.heading": "Desplegar la identidad emitida mediante un conector",
  "wizard.integrations.connector.targetName": "Nombre del destino",
  "wizard.integrations.connector.config": "Configuración del destino del conector",
  "wizard.integrations.externalCA.heading": "Emitir con una CA ascendente configurada",
  "wizard.integrations.externalCA.label": "CA externa",
  "wizard.integrations.externalCA.none": "No hay una CA ascendente configurada",
  "wizard.integrations.externalCA.csr": "CSR de la CA externa",
  "wizard.integrations.externalCA.dns": "Nombres DNS de la CA externa",
  "wizard.integrations.externalCA.dnsPlaceholder": "pagos.example.com, api.example.com",
  "wizard.integrations.lease.heading": "Emitir un secreto dinámico de corta duración",
  "wizard.integrations.lease.provider": "Proveedor del arrendamiento",
  "wizard.integrations.lease.role": "Rol del arrendamiento",
  "wizard.integrations.skip": "Omitir por ahora la prueba de integraciones",
  "codesign.digest.placeholder": "sha256:<64 caracteres hexadecimales>",
  "codesign.receipt.fulcioSAN": "SAN de Fulcio verificado",
  "codesign.receipt.transparencyDestination": "Destino de transparencia",
  "codesign.receipt.signatureBase64": "Firma (base64)",
  "codesign.receipt.downloadSignature": "Descargar firma",
  "operations.status.queued": "En cola",
  "certificates.ingest.pem.label": "Pegar el certificado",
  "certificates.ingest.pem.description": "Solo PEM de certificado público: las claves privadas nunca pertenecen a este formulario.",
  "certificates.ingest.placement.label": "Asignar propiedad",
  "certificates.ingest.placement.description": "Elija el propietario responsable y registre dónde está desplegado el certificado.",
  "certificates.ingest.review.label": "Revisar e ingerir",
  "certificates.ingest.review.description": "El certificado se incorpora al inventario de inmediato y aparece en la salud del entorno.",
  "certificates.ingest.nextPlacement": "Siguiente: asignar propiedad",
  "certificates.ingest.nextReview": "Siguiente: revisar",
  "certificates.ingest.ownerUnassigned": "Sin propietario (asignar más tarde)",
  "nav.item.journeys": "Recorridos",
  "journeys.eyebrow": "Rutas guiadas",
  "journeys.description":
    "Los recorridos documentados del operador como listas vivas: cada paso lleva con un clic al lugar correcto y los pasos terminados se marcan solos a partir de datos servidos.",
  "journeys.listLabel": "Recorridos disponibles",
  "journeys.progress": "{done} de {total} pasos completados",
  "journeys.census.verified": "Ruta verificada · cableado publicado {passed}/{total}",
  "journeys.open": "Llévame allí",
  "journeys.refresh": "Actualizar estado",
  "journeys.doc": "Guía de referencia",
  "journeys.status.done": "Hecho",
  "journeys.status.pending": "Pendiente",
  "journeys.fc.title": "Primer certificado",
  "journeys.fc.description": "De un plano de control vacío a un certificado emitido e inventariado.",
  "journeys.fc.wizard.title": "Conectar un emisor e inscribir un agente",
  "journeys.fc.wizard.body": "El asistente de configuración aprovisiona la CA interna respaldada por el firmador y pone en línea su primer agente.",
  "journeys.fc.request.title": "Solicitar la credencial",
  "journeys.fc.request.body": "Elija un perfil y nombre la credencial: la aprobación es un paso separado, nadie se autoemite.",
  "journeys.fc.approve.title": "Aprobarla",
  "journeys.fc.approve.body": "Un segundo operador firma en la cola de aprobaciones; la emisión ocurre solo tras la puerta de control.",
  "journeys.fc.inventory.title": "Verla en el inventario",
  "journeys.fc.inventory.body": "El certificado emitido llega al inventario y empieza a contar en la salud del entorno.",
  "journeys.mig.title": "Migrar desde una CA existente",
  "journeys.mig.description": "Encuentre cada certificado que emitió la CA antigua, fije sus reglas y traslade la emisión de forma deliberada.",
  "journeys.mig.source.title": "Apuntar el descubrimiento a su entorno",
  "journeys.mig.source.body": "Cree una fuente de red que cubra los hosts y rangos que atendía la CA antigua.",
  "journeys.mig.scan.title": "Poner en cola el primer escaneo",
  "journeys.mig.scan.body": "Ejecute la fuente: los hallazgos llegan a la consola mientras el escaneo recorre sus objetivos.",
  "journeys.mig.findings.title": "Revisar lo encontrado",
  "journeys.mig.findings.body": "Gestione los certificados descubiertos desde la tabla de hallazgos: reclamar, etiquetar o descartar.",
  "journeys.mig.profile.title": "Fijar las reglas de emisión",
  "journeys.mig.profile.body": "Un perfil bloquea algoritmos, vigencias y usos antes de trasladar cualquier emisión nueva.",
  "journeys.mig.request.title": "Trasladar la nueva emisión a trstctl",
  "journeys.mig.request.body": "Solicite reemplazos contra el perfil; la puerta de aprobación mantiene el traslado deliberado.",
  "journeys.mig.health.title": "Vigilar la salud del entorno",
  "journeys.mig.health.body": "La salud del entorno distingue fuentes externas y emitidas mientras la migración vacía la CA antigua.",
  "journeys.ir.title": "Responder a un compromiso",
  "journeys.ir.description": "Delimite el radio de impacto, reemplace antes de revocar y deje un rastro de evidencia sellado.",
  "journeys.ir.blast.title": "Delimitar el radio de impacto",
  "journeys.ir.blast.body": "Seleccione la credencial comprometida en el grafo y analice: el impacto se pinta en el mapa.",
  "journeys.ir.contain.title": "Reemplazar y luego revocar",
  "journeys.ir.contain.body": "El flujo de incidentes aprovisiona el reemplazo antes de revocar la credencial comprometida.",
  "journeys.ir.verify.title": "Verificar la revocación",
  "journeys.ir.verify.body": "Confirme que la credencial aparece revocada en el inventario y que la distribución CRL la recogió.",
  "journeys.ir.evidence.title": "Recopilar la evidencia",
  "journeys.ir.evidence.body": "El rastro de auditoría y su exportación firmada son el paquete de evidencia del incidente.",
  "journeys.copy": "Copiar comando",
  "journeys.copied": "Copiado",
  "journeys.markDone": "Marcar paso como hecho",
  "journeys.undoDone": "Marcar como no hecho",
  "journeys.fleet.title": "Automatizar TLS de la flota",
  "journeys.fleet.description": "Las máquinas se inscriben y renuevan solas mediante ACME con prueba DNS-01: ningún humano custodia certificados.",
  "journeys.fleet.protocols.title": "Inspeccionar la superficie ACME",
  "journeys.fleet.protocols.body":
    "La página Protocolos muestra el directorio ACME, la vinculación de tenant, las puertas de perfil y el estado del respondedor.",
  "journeys.fleet.dns.title": "Delegar la validación DNS-01",
  "journeys.fleet.dns.body": "Apunte _acme-challenge a la zona de validación mediante CNAME; las configuraciones DNS-01 y la verificación previa viven aquí.",
  "journeys.fleet.certbot.title": "Apuntar un cliente ACME al directorio",
  "journeys.fleet.certbot.body": "Cualquier cliente ACME funciona; certbot con DNS-01 cubre comodines y hosts con puertos inaccesibles.",
  "journeys.fleet.bindings.title": "Vincular certificados a sus endpoints",
  "journeys.fleet.bindings.body": "Una sola llamada de vinculación pone en cola emisión y despliegue; los recibos llegan a Preparación de renovación.",
  "journeys.k8s.title": "Identidad de cargas en Kubernetes",
  "journeys.k8s.description": "Certificados de corta vida para cargas con atestación previa a la confianza: sin secretos estáticos en los pods.",
  "journeys.k8s.trust.title": "Registrar el atestador del clúster",
  "journeys.k8s.trust.body": "Añada el JWKS del clúster como fuente de confianza de atestación en la página Cargas: atestación antes que confianza.",
  "journeys.k8s.spiffe.title": "Habilitar la Workload API de SPIFFE",
  "journeys.k8s.spiffe.body": "Protocolos muestra los requisitos de dominio de confianza y socket más el estado del respondedor para emitir SVID.",
  "journeys.k8s.register.title": "Registrar cargas como identidades",
  "journeys.k8s.register.body": "Cada cuenta de servicio se convierte en identidad gestionada para inventariar y asignar sus certificados.",
  "journeys.k8s.integrate.title": "Elegir la ruta de integración",
  "journeys.k8s.integrate.body": "ClusterIssuer de cert-manager, CertificateSigningRequests nativos o SPIRE aguas arriba: los manifiestos están en la guía.",
  "journeys.k8s.verify.title": "Verificar que los SVID rotan",
  "journeys.k8s.verify.body": "Los certificados de cargas aparecen en el inventario y rotan solos: no hay nada estático que robar.",
  "journeys.devices.title": "Inscribir dispositivos",
  "journeys.devices.description": "Dispositivos de red y embebidos se inscriben por EST, SCEP o CMP y renuevan antes de expirar.",
  "journeys.devices.protocols.title": "Inspeccionar los registros de inscripción",
  "journeys.devices.protocols.body": "Los registros EST, SCEP y CMP, sus puertas y el estado del respondedor viven en la página Protocolos.",
  "journeys.devices.cacerts.title": "Obtener la cadena de la CA",
  "journeys.devices.cacerts.body": "Los dispositivos arrancan la confianza obteniendo la cadena de la CA del endpoint well-known de EST.",
  "journeys.devices.enroll.title": "Inscribirse con un CSR",
  "journeys.devices.enroll.body": "Envíe el CSR del dispositivo a simpleenroll; reinscriba antes de expirar con el mismo flujo.",
  "journeys.devices.bootstrap.title": "Controlar clientes limitados y MDM",
  "journeys.devices.bootstrap.body":
    "Los clientes IoT diminutos usan tokens de arranque de un solo uso; los teléfonos MDM se controlan con políticas de desafío SCEP.",
  "journeys.sec.title": "Gestionar secretos",
  "journeys.sec.description":
    "Un almacén cifrado con versionado, credenciales de corta vida, comparticiones de un solo uso, escaneo y sincronización a la nube.",
  "journeys.sec.enable.title": "Habilitar la superficie de secretos",
  "journeys.sec.enable.body": "Los secretos fallan cerrados hasta que la superficie está habilitada y existe un archivo de clave de cifrado de claves.",
  "journeys.sec.store.title": "Trabajar el almacén nativo",
  "journeys.sec.store.body": "Navegue el árbol, cree, revele una vez, rote y elimine: los metadatos son duraderos, los valores no se vuelven a mostrar.",
  "journeys.sec.engines.title": "Emitir credenciales de corta vida",
  "journeys.sec.engines.body": "Los arrendamientos dinámicos, PKI-como-secreto y las operaciones transit/KMIP viven en la pestaña Motores.",
  "journeys.sec.share.title": "Compartir sin residuo",
  "journeys.sec.share.body": "Las comparticiones de un solo uso se autodestruyen al canjearse; las claves API efímeras se revelan una vez y expiran solas.",
  "journeys.sec.scan.title": "Escanear secretos confirmados",
  "journeys.sec.scan.body": "Los escaneos de repositorios y de terceros reportan hallazgos redactados: archivo, línea y huella, nunca el valor.",
  "journeys.sec.sync.title": "Sincronizar donde leen las cargas",
  "journeys.sec.sync.body": "Envíe secretos almacenados a destinos de nube y CI; el navegador solo transmite el nombre y la clave remota.",
  "journeys.ssh.title": "SSH a escala",
  "journeys.ssh.description": "Reemplace claves SSH permanentes con certificados de corta vida de una CA central, con revocación vía KRL.",
  "journeys.ssh.source.title": "Descubrir el acceso SSH permanente",
  "journeys.ssh.source.body": "Una fuente de descubrimiento SSH encuentra las claves autorizadas en la flota y marca las huérfanas.",
  "journeys.ssh.findings.title": "Revisar los hallazgos de claves",
  "journeys.ssh.findings.body": "Gestione las claves descubiertas en la tabla de hallazgos antes de que ningún host confíe en la nueva CA.",
  "journeys.ssh.trust.title": "Desplegar la confianza en los hosts",
  "journeys.ssh.trust.body": "El despliegue registra hosts, verificaciones de salud y el plan de reversión como evidencia; la página SSH sigue el estado.",
  "journeys.ssh.issue.title": "Emitir certificados de usuario atestados",
  "journeys.ssh.issue.body": "Los certificados de usuario de corta vida exigen atestación, con principales y direcciones de origen fijados.",
  "journeys.ssh.revoke.title": "Revocar antes de expirar",
  "journeys.ssh.revoke.body": "La revocación llega a la KRL que los hosts ya descargan: sin cirugía de claves por host.",
  "journeys.ssh.retire.title": "Retirar las claves permanentes",
  "journeys.ssh.retire.body": "Cuando el acceso por certificado se sostiene, retire las claves permanentes y conserve el libro de despliegue como prueba.",
  "journeys.team.title": "Incorporar un equipo",
  "journeys.team.description": "Una porción de tenant aislada con SSO, roles, política de denegación por defecto y un rastro de auditoría firmado.",
  "journeys.team.token.title": "Emitir el token del tenant",
  "journeys.team.token.body": "Un token con ámbito de tenant es la frontera del equipo: cada recurso que toca permanece dentro del tenant.",
  "journeys.team.sso.title": "Configurar el SSO del navegador",
  "journeys.team.sso.body": "La configuración OIDC, SAML o LDAP asigna usuarios autenticados al tenant; SCIM mantiene la membresía sincronizada.",
  "journeys.team.roles.title": "Asignar roles y tokens",
  "journeys.team.roles.body": "Miembros, roles, tokens de API y bajas se administran en la pestaña de acceso de Plataforma.",
  "journeys.team.policy.title": "Activar la política de denegación por defecto",
  "journeys.team.policy.body": "Las puertas de política con doble control deciden qué se emite; la página Política explica cada decisión.",
  "journeys.team.audit.title": "Demostrarlo con la auditoría",
  "journeys.team.audit.body": "Consulte eventos en la consola y exporte el paquete de evidencia firmado para cumplimiento.",
  "journeys.pqc.title": "Agilidad criptográfica y PQC",
  "journeys.pqc.description": "Inventaríe sus algoritmos, fije las reglas y migre las credenciales vulnerables al cuántico de forma deliberada.",
  "journeys.pqc.scan.title": "Poner en cola un escaneo CBOM",
  "journeys.pqc.scan.body": "El escaneo inventaría algoritmos en endpoints TLS y configuraciones de host; Postura muestra los resultados.",
  "journeys.pqc.inventory.title": "Leer su postura criptográfica",
  "journeys.pqc.inventory.body": "Postura califica la preparación PQC y lista los activos vulnerables al cuántico que conviene migrar primero.",
  "journeys.pqc.graph.title": "Rastrear activos criptográficos en el grafo",
  "journeys.pqc.graph.body": "Los nodos de activos criptográficos muestran qué cargas y credenciales comparten una clave vulnerable.",
  "journeys.pqc.profile.title": "Fijar algoritmos en un perfil",
  "journeys.pqc.profile.body": "Un perfil restringe los algoritmos de clave permitidos para que nada nuevo se emita sobre la curva antigua.",
  "journeys.pqc.migrate.title": "Migrar y ensayar la reversión",
  "journeys.pqc.migrate.body": "El orquestador de migración EE mueve activos a objetivos ML-DSA y puede revertir una ejecución: ensáyelo.",
  "journeys.prod.title": "Operar en producción",
  "journeys.prod.description": "Un certificado real, salud en vivo, recuperación ensayada, auditoría exportable y contrapresión ajustada.",
  "journeys.prod.tls.title": "Servir con su propio certificado",
  "journeys.prod.tls.body": "Apunte el servidor a sus archivos de certificado y clave antes de que algo dependa de él.",
  "journeys.prod.health.title": "Vigilar preparación y métricas",
  "journeys.prod.health.body": "readyz comprueba db, nats y el firmador; Prometheus raspa /metrics — Postura del sistema resume el runtime.",
  "journeys.prod.backup.title": "Ensayar copia y restauración",
  "journeys.prod.backup.body": "Las copias completas cifradas solo cuentan cuando la restauración se ha ensayado de verdad.",
  "journeys.prod.audit.title": "Exportar evidencia de auditoría",
  "journeys.prod.audit.body": "Consulte decisiones de política en la consola y exporte el paquete firmado que los auditores pueden verificar.",
  "journeys.prod.resilience.title": "Ajustar límites, federación y aislamiento",
  "journeys.prod.resilience.body": "La contrapresión, la federación de región pasiva y el modo aislado se controlan por entorno; la postura revela su estado.",
  "journeys.api.title": "Construir sobre la API",
  "journeys.api.description": "Un contrato OpenAPI, una CLI con paridad total, mutaciones idempotentes y SDK tipados.",
  "journeys.api.contract.title": "Obtener el contrato",
  "journeys.api.contract.body": "El documento OpenAPI 3.1 es la fuente de verdad; el Explorador de API lo muestra en vivo.",
  "journeys.api.cli.title": "Manejarlo desde la CLI",
  "journeys.api.cli.body": "La CLI cubre todas las operaciones de la API: apúntela al servidor con dos variables de entorno.",
  "journeys.api.idempotency.title": "Hacer idempotentes las mutaciones",
  "journeys.api.idempotency.body": "Envíe una Idempotency-Key estable con cada creación para que los reintentos nunca dupliquen escrituras.",
  "journeys.api.graph.title": "Consultar el grafo de credenciales",
  "journeys.api.graph.body": "El mismo grafo que dibuja la consola es consultable: nodos, aristas, radio de impacto y alcanzabilidad.",
  "request.wizard.nextReview": "Siguiente: revisar",
  "request.wizard.ownerHint": "Prellenado con el principal de su sesión.",
  "identities.decommission.description":
    "Retire o revoque identidades en respuesta a bajas de RR. HH., terminaciones de proveedores o ventanas de inactividad.",
  "state.permissionDenied": "Permiso denegado",
  "grid.state.loading": "Cargando filas...",
  "grid.state.error": "No se pudieron cargar las filas",
  "grid.state.permissionDeniedBody": "Tu sesion no puede leer estas filas.",
  "grid.state.unavailable": "Filas no disponibles",
  "grid.state.empty": "Sin filas",
  "shell.primaryNavigation": "Principal",
  "shell.primaryNavigationDialog": "Navegación principal",
  "shell.openPrimaryNavigation": "Abrir navegación principal",
  "shell.closePrimaryNavigation": "Cerrar navegación principal",
  "shell.showPrimaryNavigation": "Mostrar barra de navegación",
  "shell.hidePrimaryNavigation": "Ocultar barra de navegación",
  "shell.navigation": "Navegación",
  "shell.openCommandPalette": "Abrir paleta de comandos",
  "shell.searchOrJump": "Buscar o ir",
  "shell.tenantContext": "Contexto del tenant",
  "shell.tenant": "Tenant",
  "shell.locale": "Idioma",
  "shell.openKeyboardShortcuts": "Abrir atajos de teclado",
  "shell.signOut": "Cerrar sesión",
  "shell.signOutFailed": "No se pudo cerrar sesión",
  "shell.routeAnnouncement": "Navegaste a {page}",
  "locale.enUS": "Inglés (Estados Unidos)",
  "locale.esES": "Español (España)",
  "locale.enXA": "Pseudolocalización inglesa",
  "locale.arXB": "Pseudolocalización RTL",
  "nav.section.needsAction": "Acción requerida",
  "nav.section.needsActionWorklists": "Listas de trabajo que requieren acción",
  "nav.task.expiringSoon.label": "Vencen pronto",
  "nav.task.expiringSoon.description": "lista de certificados a 30 días",
  "nav.task.pendingApprovals.label": "Aprobaciones pendientes",
  "nav.task.pendingApprovals.description": "bandeja de emisión, rotación y revocación con doble control",
  "nav.task.highestRisk.label": "Mayor riesgo",
  "nav.task.highestRisk.description": "lista de rotación priorizada por riesgo",
  "certificates.health.heading": "Salud de certificados del entorno",
  "certificates.health.description": "Incluye inventario de certificados emitidos, importados y descubiertos.",
  "breakglass.issue.heading": "Emisión break-glass en línea",
  "breakglass.issue.description":
    "Envía un CSR, motivo, TTL y aprobaciones de operadores m-de-n; el servidor registra breakglass.issued antes de devolver el paquete.",
  "breakglass.issue.label": "Solicitud de emisión en línea (JSON)",
  "breakglass.issue.submit": "Emitir certificado break-glass",
  "breakglass.issue.busy": "Emitiendo...",
  "breakglass.issue.errorTitle": "La emisión falló",
  "breakglass.issue.invalidJson": "La solicitud de emisión debe ser un objeto JSON.",
  "breakglass.issue.status": "Emitido y auditado {count} paquete break-glass.",
  "certificates.health.stateCritical": "crítico",
  "certificates.health.stateWarning": "advertencia",
  "certificates.health.stateOk": "correcto",
  "certificates.health.totalInventory": "Inventario total",
  "certificates.health.expiring7d": "Expiran en 7 d",
  "certificates.health.expiring30d": "Expiran en 30 d",
  "certificates.health.externalSources": "Fuentes externas",
  "certificates.health.sourcePosture": "Postura por fuente",
  "certificates.health.external": "externo",
  "certificates.health.issued": "emitido",
  "certificates.health.soonestExpirations": "Vencimientos más próximos",
  "certificates.health.no90dExpirations": "Ningún certificado expira dentro de la ventana de 90 días del entorno.",
  "certificates.crl.heading": "Distribución de CRL",
  "certificates.crl.summary": "CA: {caCount}; shards: {shardCount}; seriales revocados: {revokedCount}.",
  "certificates.crl.empty": "Aún no se han publicado artefactos CRL.",
  "certificates.crl.shardPlan": "plan de {shardCount} shards",
  "certificates.crl.awaiting": "Esperando CRL",
  "certificates.crl.ca": "CA",
  "certificates.crl.full": "CRL completa",
  "certificates.crl.shards": "Shards",
  "certificates.crl.delta": "Delta",
  "certificates.crl.window": "Ventana",
  "certificates.crl.revokedCount": "{count} revocados",
  "certificates.crl.servedCount": "{count} disponibles",
  "certificates.crl.plannedCount": "{count} planificados",
  "certificates.crl.deltaBase": "base #{base}",
  "certificates.crl.nextUpdate": "siguiente {date}",
  "certificates.ct.heading": "Transparencia de certificados",
  "certificates.ct.queuedBadge": "{capability} en cola {queued}",
  "certificates.ct.certificatePEM": "PEM del certificado",
  "certificates.ct.precertificatePEM": "PEM del precertificado",
  "certificates.ct.chainPEM": "PEM de la cadena emisora",
  "certificates.ct.chainPlaceholder": "opcional",
  "certificates.ct.logs": "Logs CT",
  "certificates.ct.logsPlaceholder": "https://ct.example.com",
  "certificates.ct.allowPrivate": "Permitir endpoint privado de log",
  "certificates.ct.queueing": "Encolando...",
  "certificates.ct.queue": "Encolar envío CT",
  "certificates.ct.errorTitle": "No se pudo encolar el envío CT",
  "certificates.ct.acceptedOne": "{count} destino de log aceptado.",
  "certificates.ct.acceptedMany": "{count} destinos de log aceptados.",
  "certificates.ct.errorCertificateRequired": "El PEM del certificado es obligatorio.",
  "certificates.ct.errorLogRequired": "Se requiere al menos un log CT.",
  "certificates.ct.action": "encolar envío de Transparencia de certificados",
  "certificates.rogue.heading": "Detección de certificados no autorizados",
  "certificates.rogue.description":
    "Marca hallazgos inesperados de Transparencia de certificados y certificados activos fuera de la política de clave, vigencia, propietario o emisor.",
  "certificates.rogue.findingBadge": "{count} hallazgos",
  "certificates.rogue.metricRogue": "No autorizado",
  "certificates.rogue.metricNonCompliant": "No conforme",
  "certificates.rogue.metricCT": "Hallazgos CT",
  "certificates.rogue.metricHigh": "Alto o crítico",
  "certificates.rogue.empty": "No hay certificados no autorizados o no conformes en la postura actual.",
  "certificates.rogue.caption": "Hallazgos de certificados no autorizados y no conformes",
  "certificates.rogue.columnSubject": "Sujeto",
  "certificates.rogue.columnStatus": "Estado",
  "certificates.rogue.columnSeverity": "Severidad",
  "certificates.rogue.columnEvidence": "Evidencia",
  "certificates.rogue.columnRecommendation": "Recomendación",
  "certificates.rogue.policyRogue": "No autorizado",
  "certificates.rogue.policyNonCompliant": "No conforme",
  "certificates.rogue.typeCTUnexpected": "Emisión CT inesperada",
  "certificates.rogue.typeNotInInventory": "Fuera del inventario",
  "certificates.rogue.typeWeakKey": "Clave débil",
  "certificates.rogue.typeLifetime": "Vigencia excede la política",
  "certificates.rogue.typeExpiredActive": "Expirado mientras activo",
  "certificates.rogue.typeOwnerMissing": "Falta propietario",
  "certificates.rogue.typeIssuerMissing": "Falta emisor",
  "certificates.rogue.riskScore": "{score} riesgo",
  "nav.group.overview": "Resumen",
  "nav.group.inventoryDiscovery": "Descubrir e inventariar",
  "nav.group.issuanceCas": "Emitir y renovar",
  "nav.group.protocols": "Protocolos",
  "nav.group.secrets": "Secretos",
  "nav.group.connectorsPlugins": "Conectores y plugins",
  "nav.group.riskInsight": "Supervisar postura",
  "nav.group.incidentsJit": "Aprobar y responder",
  "nav.group.governance": "Gobierno",
  "nav.group.platform": "Administrar",
  "nav.item.dashboard": "Panel",
  "nav.item.setUp": "Configuración inicial",
  "nav.item.requestCredential": "Solicitar credencial",
  "nav.item.certificates": "Certificados",
  "nav.item.identities": "Identidades",
  "nav.item.owners": "Propietarios",
  "nav.item.agents": "Agentes",
  "nav.item.discovery": "Descubrimiento",
  "nav.item.workloads": "Cargas de trabajo",
  "nav.item.profiles": "Perfiles de certificado",
  "nav.item.issuance": "Emisión",
  "nav.item.caHierarchy": "Jerarquía de CA",
  "caHierarchy.discovery.heading": "Inventario de descubrimiento de CA",
  "caHierarchy.discovery.description":
    "Las CA ascendentes públicas, las CA ascendentes privadas y las autoridades importadas de la jerarquía de CA se normalizan en un inventario de solo lectura.",
  "caHierarchy.discovery.summaryPublic": "Públicas",
  "caHierarchy.discovery.summaryPrivate": "Privadas",
  "caHierarchy.discovery.summaryUpstream": "Ascendentes",
  "caHierarchy.discovery.summaryAuthorities": "Autoridades",
  "caHierarchy.discovery.emptyTitle": "No se descubrieron CA",
  "caHierarchy.discovery.emptyBody": "Conecta una CA ascendente o importa una autoridad para completar el inventario.",
  "caHierarchy.discovery.columnName": "Nombre",
  "caHierarchy.discovery.columnScope": "Alcance",
  "caHierarchy.discovery.columnSource": "Origen",
  "caHierarchy.discovery.columnStatus": "Estado",
  "caHierarchy.discovery.columnServedPath": "Ruta de ejecución",
  "caHierarchy.discovery.scopePublic": "Pública",
  "caHierarchy.discovery.scopePrivate": "Privada",
  "caHierarchy.discovery.sourceExternal": "Registro de CA externas",
  "caHierarchy.discovery.sourceHierarchy": "Jerarquía de CA",
  "caHierarchy.discovery.signerBacked": "respaldada por firmante",
  "caHierarchy.externalIssue.heading": "Emisión saliente con CA externa",
  "caHierarchy.externalIssue.description":
    "Envía una CSR mediante una CA ascendente configurada. El navegador muestra outbox-pending mientras el servidor registra la intención de emisión de CA, y después muestra evidencia de emisión sin representar el PEM del certificado.",
  "caHierarchy.externalIssue.emptyTitle": "No hay CA externas configuradas",
  "caHierarchy.externalIssue.emptyBody": "Configura una CA ascendente antes de emitir mediante el registro de CA externas.",
  "caHierarchy.externalIssue.formHeading": "Emisión respaldada por registro",
  "caHierarchy.externalIssue.submit": "Emitir mediante CA externa",
  "caHierarchy.externalIssue.errorTitle": "Falló la emisión con CA externa",
  "caHierarchy.externalIssue.caLabel": "CA externa",
  "caHierarchy.externalIssue.caPlaceholder": "Seleccionar CA externa",
  "caHierarchy.externalIssue.commonNameLabel": "Nombre común del certificado",
  "caHierarchy.externalIssue.dnsNamesLabel": "Nombres DNS",
  "caHierarchy.externalIssue.dnsNamesPlaceholder": "service.example.com, alt.example.com",
  "caHierarchy.externalIssue.profileLabel": "Nombre de perfil",
  "caHierarchy.externalIssue.profilePlaceholder": "web-server",
  "caHierarchy.externalIssue.ttlLabel": "Días de TTL",
  "caHierarchy.externalIssue.csrLabel": "PEM de CSR",
  "caHierarchy.externalIssue.csrPlaceholder": "-----BEGIN CERTIFICATE REQUEST-----",
  "caHierarchy.externalIssue.statusHeading": "Estado de emisión",
  "caHierarchy.externalIssue.stateLabel": "Estado",
  "caHierarchy.externalIssue.state.outboxPending": "outbox-pending",
  "caHierarchy.externalIssue.state.externalCAIssued": "external-ca-issued",
  "caHierarchy.externalIssue.pathLabel": "Ruta de API",
  "caHierarchy.externalIssue.serialLabel": "Serie",
  "caHierarchy.externalIssue.issuerLabel": "Emisor",
  "caHierarchy.externalIssue.notAfterLabel": "No después de",
  "discovery.monitoring.heading": "Monitoreo continuo",
  "discovery.monitoring.metricSources": "Orígenes",
  "discovery.monitoring.metricScheduled": "Programados",
  "discovery.monitoring.metricActive": "Activos",
  "discovery.monitoring.metricRuns": "Ejecuciones",
  "discovery.monitoring.metricFindings": "Hallazgos",
  "discovery.monitoring.metricInventory": "Inventario",
  "discovery.monitoring.emptyTitle": "No hay orígenes monitoreados",
  "discovery.monitoring.createSource": "Crear origen",
  "discovery.monitoring.emptyBody": "Agrega un origen y una programación para iniciar el monitoreo continuo.",
  "discovery.monitoring.caption": "Postura del repositorio de monitoreo continuo",
  "discovery.monitoring.columnSource": "Origen",
  "discovery.monitoring.columnSchedule": "Programación",
  "discovery.monitoring.columnLastRun": "Última ejecución",
  "discovery.monitoring.columnFindings": "Hallazgos",
  "discovery.monitoring.columnInventory": "Inventario",
  "discovery.monitoring.columnRepository": "Repositorio",
  "discovery.monitoring.unscheduled": "sin programación",
  "discovery.sourceForm.csvReadFailed": "No se pudo leer la carga CSV.",
  "discovery.shadow.heading": "Postura NHI sombra",
  "discovery.shadow.metricFindings": "Hallazgos",
  "discovery.shadow.metricUnmanaged": "No administrados",
  "discovery.shadow.metricUnregistered": "Sin registrar",
  "discovery.shadow.metricOwnerless": "Sin propietario",
  "discovery.shadow.metricHigh": "Alto o crítico",
  "discovery.shadow.metricAnalyzed": "Analizados",
  "discovery.shadow.kindBreakdown": "Desglose por tipo",
  "discovery.shadow.surfaceBreakdown": "Desglose por superficie",
  "discovery.shadow.caption": "Hallazgos NHI sombra",
  "discovery.shadow.columnSurface": "Superficie",
  "discovery.shadow.columnSeverity": "Severidad",
  "discovery.shadow.columnRecommendation": "Recomendación",
  "discovery.shadow.empty": "Sin hallazgos NHI sombra.",
  "discovery.findings.filters": "Filtros de hallazgos de descubrimiento",
  "discovery.findings.filterStatus": "Estado de triaje",
  "discovery.findings.filterStatusAll": "Todos los estados",
  "discovery.findings.filterOwner": "Propietario",
  "discovery.findings.filterOwnerAll": "Todos los propietarios",
  "discovery.findings.filterTeam": "Equipo",
  "discovery.findings.filterTeamAll": "Todos los equipos",
  "discovery.findings.filterTag": "Etiqueta",
  "discovery.findings.filterTagAll": "Todas las etiquetas",
  "discovery.findings.caption": "Hallazgos de descubrimiento",
  "discovery.findings.columnStatus": "Estado",
  "discovery.findings.columnKind": "Tipo",
  "discovery.findings.columnReference": "Referencia",
  "discovery.findings.columnOwner": "Propietario",
  "discovery.findings.columnTeam": "Equipo",
  "discovery.findings.columnTags": "Etiquetas",
  "discovery.findings.columnSource": "Origen",
  "discovery.findings.columnRisk": "Riesgo",
  "discovery.findings.columnDiscovered": "Descubierto",
  "discovery.findings.columnActions": "Acciones",
  "discovery.findings.columnFingerprint": "Huella",
  "discovery.findings.noMatches": "Ningún hallazgo coincide con estos filtros.",
  "discovery.findings.details": "Detalles",
  "discovery.findings.claim": "Reclamar",
  "discovery.findings.dismiss": "Descartar",
  "discovery.findings.rotate": "Rotar",
  "discovery.findings.revoke": "Revocar",
  "discovery.findings.decommission": "Retirar",
  "discovery.findings.remediate": "Remediar",
  "discovery.findings.detailHeading": "Detalle del hallazgo",
  "discovery.findings.close": "Cerrar",
  "discovery.findings.triageReason": "Motivo",
  "discovery.findings.managedIdentity": "Identidad administrada",
  "discovery.findings.claimSubmit": "Reclamar como administrado",
  "discovery.findings.dismissSubmit": "Descartar hallazgo",
  "discovery.findings.claimError": "No se pudo reclamar el hallazgo de descubrimiento",
  "discovery.findings.dismissError": "No se pudo descartar el hallazgo de descubrimiento",
  "discovery.findings.identityRequired": "Reclama este hallazgo en una identidad administrada antes de ejecutar acciones de ciclo de vida.",
  "discovery.findings.actionError": "No se pudo ejecutar la acción del hallazgo de descubrimiento",
  "discovery.findings.rotateQueued": "Playbook de rotación iniciado para {ref}.",
  "discovery.findings.revokeQueued": "Revocación solicitada para {ref}.",
  "discovery.findings.decommissionQueued": "Retiro solicitado para {ref}.",
  "discovery.findings.remediationQueued": "Playbook de remediación iniciado para {ref}.",
  "discovery.findings.statusUnmanaged": "No administrado",
  "discovery.findings.statusInvestigating": "En investigación",
  "discovery.findings.statusManaged": "Administrado",
  "discovery.findings.statusDismissed": "Descartado",
  "caHierarchy.offline.heading": "Raíz sin conexión",
  "caHierarchy.offline.description":
    "Importa una raíz pública, genera una CSR de intermediaria retenida por el firmante e importa la intermediaria firmada por la raíz.",
  "caHierarchy.offline.errorTitle": "Falló la acción de raíz sin conexión",
  "caHierarchy.offline.rootImport": "Importación de raíz",
  "caHierarchy.offline.startRootCeremony": "Iniciar ceremonia de raíz sin conexión",
  "caHierarchy.offline.importRoot": "Importar raíz sin conexión",
  "caHierarchy.offline.commonName": "Nombre común",
  "caHierarchy.offline.permittedDNSDomains": "Dominios DNS permitidos",
  "caHierarchy.offline.maxPathLen": "Longitud máxima de ruta",
  "caHierarchy.offline.ttlDays": "Días de TTL",
  "caHierarchy.offline.rootCertPEM": "PEM del certificado de raíz sin conexión",
  "caHierarchy.offline.rootCeremonyID": "ID de ceremonia de raíz",
  "caHierarchy.offline.intermediate": "Intermediaria",
  "caHierarchy.offline.startIntermediateCeremony": "Iniciar ceremonia de intermediaria",
  "caHierarchy.offline.generateCSR": "Generar CSR del firmante",
  "caHierarchy.offline.importIntermediate": "Importar intermediaria firmada sin conexión",
  "caHierarchy.offline.parentAuthorityID": "ID de autoridad raíz sin conexión",
  "caHierarchy.offline.intermediateCeremonyID": "ID de ceremonia de intermediaria",
  "caHierarchy.offline.signerCSRPEM": "PEM de CSR del firmante",
  "caHierarchy.offline.signedIntermediatePEM": "PEM de intermediaria firmada sin conexión",
  "caHierarchy.offline.signerHandle": "Identificador del firmante",
  "caHierarchy.offline.signerOffline": "sin conexión",
  "caHierarchy.offline.placeholderCertificate": "-----BEGIN CERTIFICATE-----",
  "caHierarchy.offline.placeholderCeremonyID": "ceremony-id",
  "caHierarchy.offline.placeholderAuthorityID": "ca-authority-id",
  "caHierarchy.offline.placeholderDNSDomain": "example.internal",
  "caHierarchy.existing.heading": "Importación de CA existente",
  "caHierarchy.existing.description":
    "Vincula una cadena de certificados raíz o intermedia ya existente a un identificador de clave retenido por el firmante después de una revisión m-de-n.",
  "caHierarchy.existing.errorTitle": "Falló la importación de CA existente",
  "caHierarchy.existing.formHeading": "Importar cadena respaldada por firmante",
  "caHierarchy.existing.startCeremony": "Iniciar ceremonia de CA existente",
  "caHierarchy.existing.import": "Importar CA existente",
  "caHierarchy.existing.chainPEM": "PEM de cadena de CA existente",
  "caHierarchy.existing.ceremonyID": "ID de ceremonia de CA existente",
  "caHierarchy.existing.placeholderSignerHandle": "ca-hierarchy-imported-existing",
  "caHierarchy.existing.placeholderCeremonyID": "ID de ceremonia",
  "caHierarchy.existing.kind": "Tipo",
  "caHierarchy.existing.serial": "Serie",
  "nav.item.protocols": "Protocolos",
  "nav.item.acmeAndDns": "ACME y DNS",
  "nav.item.enrollmentProtocols": "Protocolos de inscripción",
  "nav.item.spiffe": "SPIFFE",
  "nav.item.sshCa": "CA SSH",
  "nav.item.sshTrust": "Confianza SSH",
  "sshTrust.attested.description":
    "Los certificados de usuario SSH de corta duración requieren evidencia de atestación, un aprobador, restricciones de principal, TTL, source-address y force-command. Bloquear la autoaprobación es una regla estricta, no una pista de la interfaz.",
  "sshTrust.attested.approver": "Aprobador",
  "sshTrust.attested.boundPrincipals": "Principales vinculados",
  "sshTrust.attested.sourceAddresses": "Direcciones de origen",
  "sshTrust.attested.forceCommand": "Comando forzado",
  "sshTrust.attested.resultConstraints": "aprobador {approver} | principales {principals} | origen {source} | comando {force}",
  "nav.item.codeSigning": "Firma de código",
  "nav.item.tsa": "TSA",
  "nav.item.secrets": "Secretos",
  "nav.item.nativeSecrets": "Secretos nativos",
  "nav.item.pkiSecrets": "Secretos PKI",
  "nav.item.machineLogin": "Inicio de sesión de máquina",
  "nav.item.secretSharing": "Compartición de secretos",
  "nav.item.connectors": "Conectores de despliegue",
  "nav.item.plugins": "Plugins",
  "nav.item.risk": "Riesgo",
  "nav.item.posture": "Postura criptográfica",
  "nav.item.graph": "Grafo de credenciales",
  "nav.item.assistant": "Asistente",
  "assistant.mcp.writeToolsNeedControls": "Las herramientas MCP con escritura requieren controles específicos de operación",
  "assistant.mcp.writeToolsSubjectFormDisabled": "El Asistente no las invoca con el formulario de solo lectura para sujeto.",
  "assistant.runtime.personalData": "Datos personales",
  "assistant.runtime.statusLoading": "El estado de runtime se esta cargando.",
  "assistant.runtime.piiEgress.redactLabel": "Redactados antes de la salida al modelo",
  "assistant.runtime.piiEgress.redactDetail": "Los datos personales se eliminan antes de que los prompts salgan del plano de control.",
  "assistant.runtime.piiEgress.blockLabel": "Bloqueados al detectar",
  "assistant.runtime.piiEgress.blockDetail": "Los prompts con datos personales se rechazan antes de la salida al modelo.",
  "assistant.runtime.piiEgress.allowLabel": "Permitidos por politica",
  "assistant.runtime.piiEgress.allowDetail": "Los datos personales pueden salir solo bajo una politica explicita del operador.",
  "assistant.runtime.piiEgress.unknownLabel": "Desconocido",
  "assistant.runtime.piiEgress.unknownDetail": "Trata la salida de datos personales como no confirmada hasta que se actualice el estado de runtime.",
  "nav.item.incidents": "Incidentes",
  "nav.item.approvals": "Aprobaciones",
  "nav.item.audit": "Auditoría",
  "nav.item.ownership": "Propiedad",
  "nav.item.rbac": "RBAC",
  "nav.item.policy": "Política",
  "policy.overview.description":
    "Las mutaciones de emision, despliegue y revocacion pasan por la compuerta OPA/Rego de denegacion predeterminada, separacion RA, aprobacion de doble control y comprobaciones de perfil vinculado antes de emitir cambios de estado.",
  "policy.enforcement.heading": "Ruta de aplicacion",
  "policy.enforcement.description":
    "El navegador no envia un id de tenant ni salta la politica. Pide al flujo de ciclo de vida que cambie el estado; el backend evalua la politica y emite el evento o devuelve un problema cerrado por seguridad.",
  "policy.enforcement.auditPrefix":
    "Las decisiones son eventos de evidencia. Usa Auditoria para inspeccionar registros allow, deny y errores de evaluacion con actor, recurso, hash y payload del flujo de eventos. Los errores de accion siguen apareciendo donde el operador inicio el flujo en",
  "policy.enforcement.identitiesLink": "Identidades",
  "policy.enforcement.auditSuffix": ".",
  "policy.enforcement.policyDecisionsLink": "Abrir decisiones de politica en Auditoria",
  "policy.enforcement.profileEvaluationsLink": "Abrir evaluaciones de perfil en Auditoria",
  "policy.compliance.heading": "Postura e informes de cumplimiento",
  "policy.compliance.description":
    "Los paquetes de evidencia son exportaciones firmadas creadas desde el registro de auditoria y el inventario criptografico. Muestran lo que trstctl puede probar y lo que tu organizacion aun debe atestar; son evidencia, no certificacion.",
  "policy.compliance.frameworkGroup": "Marco de cumplimiento",
  "policy.compliance.loadingEvidencePack": "Cargando paquete de evidencia.",
  "policy.compliance.evidencePackUnavailable": "Paquete de evidencia no disponible",
  "policy.versions.heading": "Versiones de politica",
  "policy.versions.description":
    "Las versiones activas de politica de ciclo de vida se comprueban antes de la activacion, se registran como eventos policy.version y se aplican antes de ejecutar cambios de ciclo de vida.",
  "policy.versions.descriptionLabel": "Descripcion",
  "policy.versions.changeRef": "Ref. de cambio",
  "policy.versions.evidenceRefs": "Refs. de evidencia",
  "policy.versions.lifecycleModule": "Modulo Rego de ciclo de vida",
  "policy.versions.authoring": "Creando...",
  "policy.versions.authorVersion": "Crear version",
  "policy.versions.activePolicy": "Politica activa",
  "policy.versions.status": "Estado",
  "policy.versions.moduleHash": "Hash del modulo",
  "policy.versions.activated": "Activada",
  "policy.versions.notActivated": "no activada",
  "policy.versions.noActive": "No hay ninguna version de politica activa.",
  "policy.versions.loading": "Cargando versiones de politica.",
  "policy.versions.unavailableTitle": "Versiones de politica no disponibles",
  "policy.versions.tableLabel": "Versiones de politica",
  "policy.versions.hash": "Hash",
  "policy.versions.change": "Cambio",
  "policy.versions.actions": "Acciones",
  "policy.versions.activating": "Activando...",
  "policy.versions.activate": "Activar",
  "policy.versions.rollingBack": "Revirtiendo...",
  "policy.versions.rollback": "Revertir",
  "policy.versions.empty": "No hay versiones de politica.",
  "policy.framework.pciDss": "PCI DSS",
  "policy.framework.hipaa": "HIPAA",
  "policy.framework.soc2": "SOC 2",
  "policy.framework.nist80053": "NIST 800-53",
  "policy.framework.nistCsf20": "NIST CSF 2.0",
  "policy.framework.fedramp": "FedRAMP",
  "policy.framework.cmmc20": "CMMC 2.0",
  "policy.framework.cnsa20": "CNSA 2.0",
  "policy.framework.cabfBR": "BR del Foro CA/B",
  "policy.framework.fips140": "FIPS 140",
  "policy.framework.commonCriteria": "Criterios comunes",
  "policy.framework.webtrust": "WebTrust",
  "policy.framework.etsi": "ETSI",
  "policy.framework.eidas": "eIDAS",
  "policy.framework.nis2": "NIS2",
  "policy.reportType.inventorySnapshot": "Instantánea de inventario",
  "policy.reportType.frameworkEvidencePack": "Paquete de evidencia del marco",
  "policy.reportType.cbomPosture": "Postura CBOM",
  "policy.reportType.auditSummary": "Resumen de auditoría",
  "policy.reportType.nhiComplianceMapping": "Mapeo de cumplimiento NHI",
  "policy.reporting.loading": "Cargando cobertura de informes.",
  "policy.reporting.unavailableTitle": "Cobertura de informes no disponible",
  "policy.reporting.schedule": "Programación",
  "policy.reporting.framework": "Marco",
  "policy.reporting.reportType": "Tipo de informe",
  "policy.reporting.cadenceDays": "Días de cadencia",
  "policy.reporting.recipientRef": "Ref. de destinatario",
  "policy.reporting.scheduling": "Programando...",
  "policy.reporting.createSchedule": "Crear programación",
  "policy.reporting.heading": "Informe de inventario de cumplimiento",
  "policy.reporting.generated": "{capability} generado {date}",
  "policy.reporting.auditExport": "audit_export",
  "policy.reporting.inventoryRows": "Filas de inventario",
  "policy.reporting.certificates": "Certificados",
  "policy.reporting.cryptoAssets": "Activos criptográficos",
  "policy.reporting.discoverySchedules": "Programaciones de descubrimiento",
  "policy.reporting.frameworks": "Marcos",
  "policy.reporting.reportTypes": "Tipos de informe",
  "policy.reporting.schedules": "Programaciones",
  "policy.reporting.enabledSchedules": "Programaciones activas",
  "policy.reporting.reportTypeList": "Tipos de informe",
  "policy.reporting.routeList": "Rutas de API",
  "policy.reporting.tableCaption": "Programaciones de informes de cumplimiento",
  "policy.reporting.type": "Tipo",
  "policy.reporting.cadence": "Cadencia",
  "policy.reporting.nextRun": "Próxima ejecución",
  "policy.reporting.empty": "Aún no hay programaciones de informes.",
  "policy.accessChange.heading": "Aprobaciones de cambios de acceso",
  "policy.accessChange.description":
    "Las solicitudes vinculan cambios de acceso NHI con evidencia de PR, ticket o CAB antes de que un revisor distinto apruebe o deniegue el cambio.",
  "policy.accessChange.action": "Acción",
  "policy.accessChange.risk": "Riesgo",
  "policy.accessChange.approvals": "Aprobaciones",
  "policy.accessChange.changeRef": "Ref. de cambio",
  "policy.accessChange.nhiId": "ID NHI",
  "policy.accessChange.nhiKind": "Tipo NHI",
  "policy.accessChange.displayName": "Nombre visible",
  "policy.accessChange.resource": "Recurso",
  "policy.accessChange.entitlement": "Derecho",
  "policy.accessChange.changeUrl": "URL de cambio",
  "policy.accessChange.evidenceRefs": "Refs. de evidencia",
  "policy.accessChange.reason": "Razón",
  "policy.accessChange.opening": "Abriendo...",
  "policy.accessChange.openRequest": "Abrir solicitud",
  "policy.accessChange.loading": "Cargando solicitudes de cambio de acceso.",
  "policy.accessChange.unavailableTitle": "Solicitudes de cambio de acceso no disponibles",
  "policy.accessChange.listLabel": "Solicitudes de cambio de acceso",
  "policy.accessChange.empty": "No hay solicitudes de cambio de acceso.",
  "policy.accessChange.changeSystem": "Sistema de cambio",
  "policy.accessChange.status": "Estado",
  "policy.accessChange.nhi": "NHI",
  "policy.accessChange.requestEvidence": "Evidencia de solicitud",
  "policy.accessChange.changeReason": "Razón del cambio",
  "policy.accessChange.decisionReason": "Razón de decisión",
  "policy.accessChange.requiredForDenial": "Obligatorio para denegar",
  "policy.accessChange.approve": "Aprobar",
  "policy.accessChange.deny": "Denegar",
  "policy.accessChange.terminal": "Esta solicitud es terminal.",
  "policy.accessChange.decisionsCaption": "Decisiones de cambio de acceso",
  "policy.accessChange.approver": "Aprobador",
  "policy.accessChange.decision": "Decisión",
  "policy.accessChange.evidence": "Evidencia",
  "policy.accessChange.recorded": "Registrado",
  "policy.accessChange.noEvidenceRef": "Sin ref. de evidencia",
  "policy.accessChange.openedNotice": "{name} solicitud {action} abierta desde {changeRef}.",
  "policy.accessChange.decisionNotice": "{name} marcado como {decision}.",
  "policy.dryRun.heading": "Autoría y ensayo de política",
  "policy.dryRun.description":
    "Los módulos candidatos se ejecutan contra el tenant autenticado. Los resultados incluyen decisión, digest del módulo, evento de auditoría y filas de traza acotadas.",
  "policy.dryRun.formLabel": "Ensayo de política",
  "policy.dryRun.kindLabel": "Tipo de política",
  "policy.dryRun.lifecycle": "Ciclo de vida",
  "policy.dryRun.abac": "ABAC",
  "policy.dryRun.moduleLabel": "Módulo Rego candidato",
  "policy.dryRun.inputLabel": "Entrada JSON de ensayo",
  "policy.dryRun.run": "Ejecutar ensayo",
  "policy.dryRun.running": "Ejecutando...",
  "policy.dryRun.auditLink": "Abrir eventos de auditoría de ensayo",
  "policy.dryRun.errorTitle": "Falló el ensayo de política",
  "policy.dryRun.invalidInput": "la entrada de ensayo debe ser un objeto JSON",
  "policy.dryRun.resultHeading": "Resultado de ensayo",
  "policy.dryRun.decisionError": "Error de política",
  "policy.dryRun.decisionAllow": "Permitir",
  "policy.dryRun.decisionDeny": "Denegar",
  "policy.dryRun.decisionNone": "Sin decisión",
  "policy.dryRun.metricKind": "Tipo",
  "policy.dryRun.metricValid": "Válido",
  "policy.dryRun.validYes": "sí",
  "policy.dryRun.validNo": "no",
  "policy.dryRun.metricPackage": "Paquete",
  "policy.dryRun.metricQuery": "Consulta",
  "policy.dryRun.metricDigest": "Digest del módulo",
  "policy.dryRun.metricTenant": "Tenant",
  "policy.dryRun.metricActor": "Actor",
  "policy.dryRun.metricIdempotency": "Idempotencia",
  "policy.dryRun.traceCaption": "Traza del ensayo de política",
  "policy.dryRun.traceOp": "Op",
  "policy.dryRun.traceLocation": "Ubicación",
  "policy.dryRun.traceNode": "Nodo",
  "policy.dryRun.traceMessage": "Mensaje",
  "policy.nhiCompliance.heading": "Mapeo de cumplimiento NHI",
  "policy.nhiCompliance.generated": "{capability} generado {date} · {state}",
  "policy.nhiCompliance.auditReady": "listo para auditoría",
  "policy.nhiCompliance.draft": "borrador",
  "policy.nhiCompliance.nhiRows": "Filas NHI",
  "policy.nhiCompliance.frameworks": "Marcos",
  "policy.nhiCompliance.mappedControls": "Controles mapeados",
  "policy.nhiCompliance.overprivileged": "Con privilegios excesivos",
  "policy.nhiCompliance.staleFindings": "Hallazgos obsoletos",
  "policy.nhiCompliance.staticCredentials": "Credenciales estáticas",
  "policy.nhiCompliance.evidenceRefs": "Refs. de evidencia",
  "policy.nhiCompliance.attestations": "Atestaciones",
  "policy.nhiCompliance.frameworkList": "Marcos",
  "policy.nhiCompliance.evidenceRoutes": "Rutas de evidencia",
  "policy.nhiCompliance.tableCaption": "Mapeos de controles de cumplimiento NHI",
  "policy.nhiCompliance.frameworkColumn": "Marco",
  "policy.nhiCompliance.controlColumn": "Control",
  "policy.nhiCompliance.statusColumn": "Estado",
  "policy.nhiCompliance.evidenceColumn": "Evidencia",
  "policy.nhiCompliance.mappedSignals": "{count} señales mapeadas",
  "policy.nhiCompliance.residualAttestations": "Atestaciones residuales",
  "nav.item.privacy": "Privacidad",
  "nav.item.integrate": "Integración y SDK",
  "nav.item.apiExplorer": "Explorador de API",
  "nav.item.operations": "Operaciones",
  "nav.item.notifications": "Notificaciones",
  "nav.item.platform": "Plataforma",
  "nav.item.sso": "SSO",
  "nav.item.apiDistribution": "API y distribución",
  "command.title": "Paleta de comandos",
  "command.description": "Ir a rutas o buscar metadatos de certificados, identidades y secretos.",
  "command.close": "Cerrar paleta de comandos",
  "command.searchLabel": "Buscar rutas e inventario",
  "command.searchPlaceholder": "Buscar rutas, certificados, identidades o secretos",
  "command.sourcesUnavailable": "Algunas fuentes de inventario no están disponibles temporalmente.",
  "command.searchingInventory": "Buscando inventario...",
  "command.routes": "Rutas",
  "command.inventory": "Inventario",
  "command.noResults": "Ninguna ruta o inventario coincide.",
  "command.routeDescription": "Ruta · {group}",
  "command.enter": "Intro",
  "search.kind.certificate": "Certificado",
  "search.kind.identity": "Identidad",
  "search.kind.secret": "Secreto",
  "agents.endpointDiscovery.heading": "Descubrimiento de endpoints",
  "agents.endpointDiscovery.description": "Los lotes de inventario llegan por {path} y se proyectan en hallazgos de Descubrimiento.",
  "agents.endpointDiscovery.reportPath": "Ruta de informe",
  "agents.endpointDiscovery.metadataOnly": "solo metadatos",
  "agents.endpointDiscovery.payload": "carga",
  "agents.endpointDiscovery.noKeyBytes": "sin bytes de clave",
  "agents.endpointDiscovery.filesystem": "Certificados del sistema de archivos",
  "agents.endpointDiscovery.pkcs11": "Certificados de token PKCS#11",
  "agents.endpointDiscovery.windowsStore": "Almacén de certificados de Windows",
  "agents.endpointDiscovery.k8sSecret": "Secretos TLS de Kubernetes",
  "agents.endpointDiscovery.trustStore": "Almacenes de confianza",
  "agents.endpointDiscovery.privateKey": "Material de clave privada",
  "nhi.inventory.title": "Inventario de identidades no humanas",
  "nhi.inventory.description": "cada identidad de máquina por tipo, con una lente de riesgo común",
  "nhi.inventory.total": "Identidades totales",
  "nhi.inventory.highRisk": "Riesgo alto",
  "risk.nhiPolicy.heading": "Cumplimiento de políticas de NHI",
  "risk.nhiPolicy.summary":
    "CAP-GOV-03: {violations} infracciones de política en {total} NHI gobernadas; {rotation} de rotación, {scope} de alcance, {geo} de geografía, {expiry} de expiración, {purpose} de propósito.",
  "risk.nhiPolicy.loading": "Cargando cumplimiento de políticas de NHI.",
  "risk.nhiPolicy.unavailableTitle": "Cumplimiento de políticas de NHI no disponible",
  "risk.nhiPolicy.empty": "No se detectaron infracciones de política de NHI.",
  "risk.nhiPolicy.caption": "Infracciones de cumplimiento de políticas de NHI",
  "risk.nhiPolicy.nhi": "NHI",
  "risk.nhiPolicy.violations": "Infracciones",
  "risk.nhiPolicy.envelope": "Límite permitido",
  "risk.nhiPolicy.envelopeValue": "Alcances: {scopes} / Geos: {geos}",
  "risk.nhiPolicy.none": "ninguno",
  "risk.nhiPolicy.recommendation": "Recomendación",
  "risk.nhiOverprivilege.heading": "Sobreprivilegio de NHI",
  "risk.nhiOverprivilege.summary": "CAP-POST-01: {overprivileged} sobreprivilegiadas de {total} NHI con uso observado; {unused} permisos sin uso.",
  "risk.nhiOverprivilege.loading": "Cargando postura de NHI.",
  "risk.nhiOverprivilege.unavailableTitle": "Postura de NHI no disponible",
  "risk.nhiOverprivilege.empty": "No se detectó alcance excesivo respaldado por uso.",
  "risk.nhiOverprivilege.caption": "Recomendaciones de sobreprivilegio de NHI",
  "risk.nhiOverprivilege.nhi": "NHI",
  "risk.nhiOverprivilege.severity": "Severidad",
  "risk.nhiOverprivilege.unusedGrants": "Permisos sin uso",
  "risk.nhiOverprivilege.recommendation": "Recomendación de privilegio mínimo",
  "risk.nhiStale.heading": "NHI obsoletas y dormidas",
  "risk.nhiStale.summary":
    "CAP-POST-02: {findings} obsoletas, sin uso, huérfanas o dormidas de {total} NHI analizadas; {dormant} dormidas, {orphaned} huérfanas.",
  "risk.nhiStale.loading": "Cargando postura de NHI obsoletas.",
  "risk.nhiStale.unavailableTitle": "Postura de NHI obsoletas no disponible",
  "risk.nhiStale.empty": "No se detectó evidencia de NHI obsoletas, sin uso, huérfanas o dormidas.",
  "risk.nhiStale.caption": "Recomendaciones para NHI obsoletas y dormidas",
  "risk.nhiStale.nhi": "NHI",
  "risk.nhiStale.finding": "Hallazgo",
  "risk.nhiStale.age": "Antigüedad",
  "risk.nhiStale.ageValue": "{activity}d actividad / {created}d creada",
  "risk.nhiStale.recommendation": "Recomendación",
  "risk.contextual.heading": "Prioridades contextuales",
  "risk.contextual.summary":
    "CAP-POST-05: {priorities} priorizadas de {total} credenciales; {highBlast} de alto radio de impacto, {weakCrypto} con contexto criptográfico débil.",
  "risk.contextual.loading": "Cargando prioridades contextuales.",
  "risk.contextual.unavailableTitle": "Prioridades contextuales no disponibles",
  "risk.contextual.empty": "No se detectaron prioridades de riesgo contextual.",
  "risk.contextual.caption": "Prioridades de riesgo contextual por radio de impacto",
  "risk.contextual.credential": "Credencial",
  "risk.contextual.priority": "Prioridad",
  "risk.contextual.blastRadius": "Radio de impacto",
  "risk.contextual.action": "Acción",
  "risk.contextual.scoreValue": "{contextual} contextual / {base} base",
  "risk.contextual.blastValue": "{total} afectadas; {resources} recursos, {cryptoAssets} activos criptográficos",
  "risk.nhiStatic.heading": "Credenciales estáticas",
  "risk.nhiStatic.summary":
    "CAP-POST-03: {findings} estáticas o de larga duración de {total} NHI analizadas; {longLived} de larga duración, {staticCredentials} estáticas.",
  "risk.nhiStatic.loading": "Cargando postura de credenciales estáticas.",
  "risk.nhiStatic.unavailableTitle": "Postura de credenciales estáticas no disponible",
  "risk.nhiStatic.empty": "No se detectó evidencia de credenciales estáticas o de larga duración.",
  "risk.nhiStatic.caption": "Recomendaciones para credenciales estáticas",
  "risk.nhiStatic.nhi": "NHI",
  "risk.nhiStatic.finding": "Hallazgo",
  "risk.nhiStatic.lifetime": "Vida útil",
  "risk.nhiStatic.lifetimeValue": "{age}d de edad / {ttl}d TTL / {rotation}d rotación",
  "risk.nhiStatic.recommendation": "Recomendación",
  "risk.nhiExposure.heading": "Despliegues NHI expuestos",
  "risk.nhiExposure.summary":
    "CAP-POST-04: {findings} hallazgos de exposición en {total} NHI analizadas; {exposed} expuestas a internet, {weakAuth} con autenticación débil, {insecureTransport} con transporte inseguro.",
  "risk.nhiExposure.loading": "Cargando postura de NHI expuestas.",
  "risk.nhiExposure.unavailableTitle": "Postura de NHI expuestas no disponible",
  "risk.nhiExposure.empty": "No se detectó evidencia de NHI expuestas a internet o despliegues inseguros.",
  "risk.nhiExposure.caption": "Recomendaciones para despliegues NHI expuestos",
  "risk.nhiExposure.nhi": "NHI",
  "risk.nhiExposure.finding": "Hallazgo",
  "risk.nhiExposure.exposure": "Exposición",
  "risk.nhiExposure.exposureValue": "{level} / {auth} / {transport}",
  "risk.nhiExposure.unknown": "desconocido",
  "risk.nhiExposure.recommendation": "Recomendación",
  "identities.decommission.ariaLabel": "Retiro de NHI",
  "identities.decommission.signal": "Señal",
  "identities.decommission.subject": "Sujeto",
  "identities.decommission.vendor": "Proveedor",
  "identities.decommission.inactiveBefore": "Inactivo antes de",
  "identities.decommission.departure": "Salida",
  "identities.decommission.vendorTerm": "Fin de proveedor",
  "identities.decommission.inactivity": "Inactividad",
  "identities.decommission.submit": "Retirar",
  "identities.decommission.reasonPlaceholder": "CAB-1234",
  "owners.attribution.heading": "Atribución de propiedad",
  "owners.attribution.loading": "Cargando atribución de propiedad...",
  "owners.attribution.error": "No se pudo cargar la atribución de propiedad",
  "owners.attribution.ariaLabel": "Atribución de propiedad de NHI",
  "owners.attribution.emptyTitle": "Sin filas de atribución",
  "owners.attribution.emptyMessage": "No hay NHI administradas o descubiertas disponibles para atribución.",
  "owners.attribution.nhi": "NHI",
  "owners.attribution.kind": "Tipo",
  "owners.attribution.owner": "Propietario",
  "owners.attribution.ownerKind": "Tipo de propietario",
  "owners.attribution.source": "Origen",
  "owners.attribution.unattributed": "Sin atribución",
  "owners.attribution.orphaned": "huérfano",
  "notifications.channels.heading": "Cobertura de canales",
  "notifications.channels.configuredCount": "{count} configurados",
  "notifications.channels.unavailableTitle": "Canales de notificación no disponibles",
  "notifications.channels.loadError": "No se pudieron cargar los canales de notificación",
  "notifications.channels.configured": "configurado",
  "notifications.channels.unconfigured": "sin configurar",
  "notifications.channels.authoringHeading": "Autoría de canales",
  "notifications.channels.type": "Tipo de canal",
  "notifications.channels.label": "Etiqueta visible",
  "notifications.channels.endpointUrl": "URL de endpoint",
  "notifications.channels.credentialRef": "Referencia de credencial del canal",
  "notifications.channels.enabled": "habilitado",
  "notifications.channels.disabled": "deshabilitado",
  "notifications.channels.save": "Guardar canal",
  "notifications.channels.saving": "Guardando...",
  "notifications.channels.saved": "Canal guardado",
  "notifications.channels.saveError": "No se pudo guardar el canal de notificación",
  "notifications.routing.heading": "Políticas de enrutamiento",
  "notifications.routing.description": "Asigna niveles de severidad a canales configurados, define propietario y previsualiza la cadencia del resumen.",
  "notifications.routing.loadError": "No se pudieron cargar las políticas de enrutamiento de notificaciones",
  "notifications.routing.createError": "No se pudo crear la política de enrutamiento de notificaciones",
  "notifications.routing.testError": "No se pudo encolar la prueba del canal de notificación",
  "notifications.routing.policyCreated": "Política de enrutamiento guardada",
  "notifications.routing.testQueued": "Prueba de canal encolada",
  "notifications.routing.name": "Nombre de política",
  "notifications.routing.ownerRef": "Referencia de propietario",
  "notifications.routing.ownerEmail": "Correo de propietario",
  "notifications.routing.digestInterval": "Intervalo de resumen",
  "notifications.routing.intervalOneHour": "1 hora",
  "notifications.routing.intervalTwelveHours": "12 horas",
  "notifications.routing.intervalOneDay": "24 horas",
  "notifications.routing.intervalSevenDays": "7 días",
  "notifications.routing.defaultChannels": "Canales predeterminados",
  "notifications.routing.criticalChannels": "Canales críticos",
  "notifications.routing.warningChannels": "Canales de advertencia",
  "notifications.routing.lowChannels": "Canales bajos",
  "notifications.routing.save": "Guardar política",
  "notifications.routing.saving": "Guardando...",
  "notifications.routing.testHeading": "Prueba de entrega",
  "notifications.routing.channel": "Canal",
  "notifications.routing.severity": "Severidad",
  "notifications.routing.testSubject": "Sujeto de prueba",
  "notifications.routing.credentialRef": "Referencia de credencial",
  "notifications.routing.sendTest": "Encolar prueba",
  "notifications.routing.testing": "Encolando...",
  "notifications.routing.noPolicies": "Aún no hay políticas de enrutamiento.",
  "notifications.routing.owner": "Propietario",
  "notifications.routing.nextDigest": "Próximo resumen",
  "notifications.error.unavailable": "Notificaciones no disponibles",
  "notifications.error.loadFailed": "No se pudieron cargar las notificaciones",
  "notifications.action.markedRead": "Notificación marcada como leída",
  "notifications.action.markReadFailed": "Falló marcar como leída",
  "notifications.action.markReadLoadFailed": "No se pudo marcar la notificación como leída",
  "notifications.action.requeued": "Notificación reencolada",
  "notifications.action.requeueFailed": "Falló reencolar",
  "notifications.action.requeueLoadFailed": "No se pudo reencolar la notificación",
  "notifications.queue.tablist": "Colas de notificaciones",
  "notifications.queue.all": "Todas",
  "notifications.queue.deadLetter": "Letra muerta",
  "notifications.filter.type": "Filtro de tipo",
  "notifications.filter.typeAll": "Todos los tipos",
  "notifications.filter.status": "Filtro de estado",
  "notifications.filter.statusAll": "Todos los estados",
  "notifications.status.pending": "pendiente",
  "notifications.status.sent": "enviada",
  "notifications.status.read": "leída",
  "notifications.status.dead": "muerta",
  "notifications.count.total": "{count} notificaciones",
  "notifications.count.unread": "{count} sin leer",
  "notifications.loading": "Cargando notificaciones...",
  "notifications.emptyTitle": "No se encontraron notificaciones",
  "notifications.emptyBody": "Ajusta los filtros o actualiza la bandeja.",
  "notifications.table.ariaLabel": "Bandeja de notificaciones",
  "notifications.table.actions": "Acciones",
  "notifications.action.markRead": "Marcar leída",
  "notifications.action.markReadAria": "Marcar notificación {id} como leída",
  "notifications.action.requeue": "Reencolar",
  "notifications.action.requeueAria": "Reencolar notificación {id}",
  "incidents.playbooks.heading": "Playbooks de remediación automatizada",
  "incidents.playbooks.description": "Ejecuta playbooks de revocación, rotación y ajuste de permisos con evidencia auditable y acciones externas en cola.",
  "incidents.playbooks.targetIdentity": "Identidad objetivo",
  "incidents.playbooks.inventoryId": "ID de inventario",
  "incidents.playbooks.connector": "Canal de entrega del playbook",
  "incidents.playbooks.providerTarget": "Destino del proveedor",
  "incidents.playbooks.removeScopes": "Permisos a quitar",
  "incidents.playbooks.rollbackReference": "Instrucciones de reversión del playbook",
  "incidents.playbooks.reason": "Motivo",
  "incidents.playbooks.defaultReason": "ajustar permisos sin uso",
  "incidents.playbooks.inventoryPlaceholder": "identity/... o finding/...",
  "incidents.playbooks.connectorPlaceholder": "aws-iam",
  "incidents.playbooks.providerTargetPlaceholder": "rol, cuenta de servicio o ruta de secreto",
  "incidents.playbooks.removeScopesPlaceholder": "subconjunto opcional separado por comas",
  "incidents.playbooks.rollbackPlaceholder": "restaurar versión anterior de política",
  "incidents.playbooks.runRightSize": "Ejecutar ajuste",
  "incidents.playbooks.running": "Ejecutando...",
  "incidents.playbooks.failedTitle": "Falló la ejecución del playbook",
  "incidents.playbooks.requiredTarget": "Se requiere identidad objetivo o ID de inventario.",
  "incidents.playbooks.loadError": "No se pudo ejecutar el playbook de remediación",
  "incidents.playbooks.recorded": "Ejecución de playbook registrada",
  "incidents.playbooks.run": "Ejecución",
  "incidents.playbooks.playbook": "Playbook",
  "incidents.playbooks.status": "Estado",
  "incidents.playbooks.externalIntent": "Intención externa",
  "incidents.playbooks.noRuns": "No se han registrado ejecuciones de playbooks de remediación.",
  "incidents.playbooks.tableCaption": "Evidencia de ejecución de playbook de remediación",
  "incidents.playbooks.target": "Destino",
  "incidents.playbooks.rollback": "Reversión",
  "incidents.playbooks.none": "ninguna",
  "incidents.ownerRemediation.heading": "Autorremediación de propietarios",
  "incidents.ownerRemediation.description":
    "Los propietarios pueden aceptar recomendaciones de mínimo privilegio desde evidencia de postura servida sin autoridad amplia de incidentes.",
  "incidents.ownerRemediation.summary": "{open} abiertas / {accepted} aceptadas",
  "incidents.ownerRemediation.failedTitle": "Falló la remediación del propietario",
  "incidents.ownerRemediation.loadError": "No se pudo aceptar la acción de remediación del propietario",
  "incidents.ownerRemediation.loading": "Cargando acciones del propietario...",
  "incidents.ownerRemediation.empty": "No hay acciones de autorremediación abiertas.",
  "incidents.ownerRemediation.caption": "Acciones de autorremediación del propietario",
  "incidents.ownerRemediation.identity": "Identidad",
  "incidents.ownerRemediation.severity": "Severidad",
  "incidents.ownerRemediation.recommendation": "Recomendación",
  "incidents.ownerRemediation.status": "Estado",
  "incidents.ownerRemediation.action": "Acción",
  "incidents.ownerRemediation.accept": "Aceptar",
  "incidents.ownerRemediation.accepting": "Aceptando...",
  "incidents.ownerRemediation.accepted": "Aceptada",
  "incidents.ownerRemediation.recorded": "Remediación del propietario registrada",
  "incidents.ownerRemediation.run": "Ejecución",
  "incidents.ownerRemediation.playbook": "Playbook",
  "incidents.ownerRemediation.externalIntent": "Intención externa",
  "incidents.response.heading": "Despacho SIEM / SOAR / ITSM",
  "incidents.response.description": "Envía un paquete de respuesta a Splunk, Jira, Slack y ServiceNow mediante eventos y fan-out de outbox.",
  "incidents.response.title": "Título de respuesta",
  "incidents.response.summary": "Resumen de respuesta",
  "incidents.response.severity": "Severidad",
  "incidents.response.correlation": "ID de correlación",
  "incidents.response.evidenceRefs": "Referencias de evidencia",
  "incidents.response.splunkEndpoint": "Endpoint HEC de Splunk",
  "incidents.response.splunkToken": "Referencia de token de Splunk",
  "incidents.response.jiraEndpoint": "Endpoint de Jira",
  "incidents.response.jiraProject": "Proyecto de Jira",
  "incidents.response.jiraToken": "Referencia de token de Jira",
  "incidents.response.slackRoute": "Ruta de Slack",
  "incidents.response.servicenowInstance": "Instancia de ServiceNow",
  "incidents.response.servicenowToken": "Referencia de token de ServiceNow",
  "incidents.response.dispatch": "Despachar respuesta",
  "incidents.response.dispatching": "Despachando...",
  "incidents.response.failedTitle": "Falló el despacho de respuesta",
  "incidents.response.titleRequired": "Se requiere título de respuesta.",
  "incidents.response.providersRequired": "Se requieren endpoints de Splunk, Jira y ServiceNow.",
  "incidents.response.loadError": "No se pudieron despachar las integraciones de respuesta",
  "incidents.response.queued": "Despacho de respuesta en cola",
  "incidents.response.dispatchId": "Despacho",
  "incidents.response.provider": "Proveedor",
  "incidents.response.destination": "Destino",
  "incidents.response.outbox": "Outbox",
  "incidents.response.status": "Estado",
  "incidents.response.severityCritical": "crítica",
  "incidents.response.severityWarning": "advertencia",
  "incidents.response.severityInformational": "informativa",
  "incidents.response.severityLow": "baja",
  "incidents.response.idempotency": "Idempotencia",
  "incidents.response.tableCaption": "Destinos de integración de respuesta",
  "incidents.response.titlePlaceholder": "Contener credencial de pagos comprometida",
  "incidents.response.optionalPlaceholder": "opcional",
  "incidents.response.evidencePlaceholder": "incident/... , audit/...",
  "incidents.response.splunkPlaceholder": "https://splunk.example/services/collector",
  "incidents.response.jiraPlaceholder": "https://jira.example",
  "incidents.response.servicenowPlaceholder": "https://example.service-now.com",
  "connectors.deliveryEvidence": "Evidencia de entrega del conector",
  "platform.scale.heading": "Orquestación de escala",
  "platform.scale.served": "CAP-SCALE-01 activo",
  "platform.scale.unavailable": "escala no disponible",
  "platform.scale.selectedTier": "Tier seleccionado",
  "platform.scale.credentialsCount": "{count} credenciales",
  "platform.scale.eventsPerDay": "Eventos/día",
  "platform.scale.monthlyCost": "Modelo de costo mensual",
  "platform.scale.unitCost": "Costo unitario",
  "platform.scale.credentialUnit": "credencial",
  "platform.scale.signerModel": "Modelo de firmante",
  "platform.scale.projectionFloor": "Piso de proyección",
  "platform.scale.projectionFloorValue": "{rate} eventos/s · retraso ≤ {lag}",
  "platform.scale.executionCaption": "Tabla de carriles de ejecución de escala",
  "platform.scale.lane": "Carril",
  "platform.scale.bulkhead": "Bulkhead",
  "platform.scale.signal": "Señal",
  "platform.scale.slo": "SLO",
  "platform.scale.releaseCaption": "Tabla de gates de release de escala",
  "platform.scale.gate": "Gate",
  "platform.scale.artifact": "Artefacto",
  "platform.scale.bandCaption": "Tabla de bandas de credenciales de escala",
  "platform.scale.band": "Banda",
  "platform.scale.tier": "Tier",
  "platform.ha.heading": "Alta disponibilidad de emisión regional",
  "platform.ha.active": "CAP-SCALE-02 activo",
  "platform.ha.unavailable": "emisión regional no disponible",
  "platform.ha.description":
    "Los ingresos regionales pueden aceptar tráfico de emisión mientras idempotencia, append de eventos, outbox, elección de líder y aislamiento del firmante mantienen cada mutación de tenant cercada.",
  "platform.ha.topology": "Topología",
  "platform.ha.writeModel": "Modelo de escritura",
  "platform.ha.rpoRto": "RPO / RTO",
  "platform.ha.rpoRtoValue": "RPO {rpo}s · RTO {rto}s",
  "platform.ha.invariants": "Invariantes de arquitectura",
  "platform.ha.regionCaption": "Tabla de ingreso de emisión regional",
  "platform.ha.region": "Región",
  "platform.ha.role": "Rol",
  "platform.ha.writeScope": "Alcance de escritura",
  "platform.ha.health": "Señal de salud",
  "platform.ha.fenceCaption": "Tabla de cercas de escritura de emisión regional",
  "platform.ha.fence": "Cerca",
  "platform.ha.scope": "Alcance",
  "platform.ha.mechanism": "Mecanismo",
  "platform.ha.failoverCaption": "Tabla de failover de emisión regional",
  "platform.ha.step": "Paso",
  "platform.ha.action": "Acción",
  "platform.ha.gate": "Gate",
  "protocols.dns01.heading": "Proveedores DNS-01",
  "protocols.dns01.caption": "Cobertura de proveedores DNS-01 de ACME",
  "protocols.dns01.provider": "Proveedor",
  "protocols.dns01.kind": "Tipo",
  "protocols.dns01.conformance": "Conformidad",
  "protocols.dns01.admission": "Admisión",
  "protocols.dns01.provenance": "Procedencia",
  "protocols.dns01.secretReferences": "Referencias de secretos",
  "protocols.dns01.capabilityGrant": "Permiso de capacidad",
  "protocols.dns01.propagationPreflight": "Preflight de propagación",
  "protocols.dns01.noRawSecretFields": "Sin campos de secreto sin procesar",
  "protocols.dns01.loading": "Cargando cobertura de proveedores DNS-01.",
  "protocols.dns01.unavailableTitle": "Proveedores DNS-01 no disponibles",
  "protocols.dns01.empty": "No se devolvieron filas del catálogo de proveedores.",
  "protocols.dns01.served": "Disponible",
  "protocols.dns01.off": "Desactivado",
  "protocols.dns01.configHeading": "Configuraciones de proveedor DNS-01",
  "protocols.dns01.configCaption": "Configuraciones DNS-01 del tenant",
  "protocols.dns01.config": "Configuración",
  "protocols.dns01.zone": "Zona",
  "protocols.dns01.policy": "Política",
  "protocols.dns01.zoneUnbound": "Zona sin enlace",
  "protocols.dns01.noMethodPolicy": "Sin regla de validación",
  "protocols.dns01.wildcardsAllowed": "Wildcards permitidos",
  "protocols.dns01.wildcardsDenied": "Wildcards denegados",
  "protocols.dns01.configLoading": "Cargando configuraciones de proveedor DNS-01.",
  "protocols.dns01.configEmptyTitle": "Configuraciones de proveedor DNS-01 no disponibles",
  "protocols.dns01.configEmpty": "No se devolvieron configuraciones de proveedor.",
  "protocols.mdm.heading": "Políticas SCEP de Intune / MDM",
  "protocols.mdm.caption": "Políticas de inscripción SCEP para MDM",
  "protocols.mdm.policy": "Política",
  "protocols.mdm.provider": "Proveedor",
  "protocols.mdm.profile": "Perfil",
  "protocols.mdm.challenge": "Challenge",
  "protocols.mdm.references": "Referencias",
  "protocols.mdm.enabled": "Habilitada",
  "protocols.mdm.disabled": "Deshabilitada",
  "protocols.mdm.rotationVersion": "Versión de rotación",
  "protocols.mdm.telemetry": "Telemetría de challenge",
  "protocols.mdm.allowed": "Permitidos",
  "protocols.mdm.denied": "Denegados",
  "protocols.mdm.replay": "Replay",
  "protocols.mdm.runtime": "Runtime",
  "protocols.mdm.runtimeConfigured": "Configurado",
  "protocols.mdm.runtimeUnknown": "Desconocido",
  "protocols.mdm.loading": "Cargando políticas SCEP de MDM.",
  "protocols.mdm.emptyTitle": "Políticas SCEP de MDM no disponibles",
  "protocols.mdm.empty": "No se devolvieron políticas SCEP de MDM.",
  "secrets.scan.description":
    "Ejecuta un escaneo de un repositorio o espacio de trabajo de build. Los hallazgos muestran solo regla, archivo, línea y la referencia de credencial redactada.",
  "secrets.scan.triageLibraryOnlyTitle": "La revisión de hallazgos del escaneo aún no está disponible",
  "secrets.scan.triageLibraryOnlyBody":
    "Los eventos de repositorio y los escaneos pueden crear hallazgos redactados aquí. Usa el flujo de descubrimiento para revisarlos hasta que se agreguen acciones específicas de escaneo.",
  "secrets.scan.mode": "Modo",
  "secrets.scan.modeWorkspace": "Espacio de trabajo",
  "secrets.scan.modeGitHistory": "Historial Git",
  "secrets.scan.customRules": "Reglas personalizadas",
  "secrets.scan.customRulesPlaceholder": "/etc/trstctl/gitleaks-rules.toml",
  "secrets.scan.customRulesYes": "sí",
  "secrets.scan.customRulesNo": "no",
  "secrets.approvals.heading": "Aprobaciones de cambios de secretos",
  "secrets.approvals.description": "Las solicitudes de rotación, actualización o eliminación denegadas aparecen aquí para revisión por un aprobador distinto.",
  "secrets.approvals.badge": "Doble control",
  "secrets.approvals.empty": "No hay cambios de secretos pendientes capturados en esta sesión del navegador.",
  "secrets.approvals.listLabel": "Aprobaciones pendientes de cambios de secretos",
  "secrets.approvals.errorTitle": "Estado de aprobación",
  "secrets.approvals.actionRotate": "Rotar/actualizar",
  "secrets.approvals.actionRecover": "Recuperar",
  "secrets.approvals.actionDelete": "Eliminar",
  "secrets.approvals.openedStatus": "Abierto {openedAt} - {status}",
  "secrets.approvals.statusCompleted": "completado",
  "secrets.approvals.statusApproved": "aprobado",
  "secrets.approvals.statusApprovedBy": "aprobado por {approver}",
  "secrets.approvals.statusApprovedWithCount": "aprobado por {approver} ({count} aprobaciones registradas)",
  "secrets.approvals.statusCount": "{count} aprobaciones registradas",
  "secrets.approvals.statusAwaiting": "esperando aprobación distinta",
  "secrets.approvals.approve": "Aprobar",
  "secrets.approvals.retry": "Reintentar",
  "secrets.approvals.approveAction": "Aprobar {action} para {name}",
  "secrets.approvals.retryAction": "Reintentar {action} para {name}",
  "secrets.approvals.requiredFallback": "El cambio de secreto requiere aprobación de doble control",
  "secrets.approvals.approvedNotice": "{approver} aprobó {action} para {name}. Reintenta el cambio para completarlo.",
  "secrets.approvals.approveFailed": "No se pudo aprobar el cambio de secreto",
  "secrets.approvals.retryFailed": "No se pudo reintentar el cambio de secreto aprobado",
  "secrets.approvals.rotateRetryNeedsForm": "Mantén el formulario de rotación en {name} con un valor de reemplazo antes de reintentar.",
  "secrets.approvals.deleteRetryNeedsForm": "Confirma {name} en el formulario de eliminación antes de reintentar.",
  "secrets.approvals.recoverRetryUnsupported": "La aprobación de recuperación está registrada; reintenta la recuperación mediante el endpoint de recuperación.",
  "secrets.approvals.rotatePending": "La rotación espera aprobación de cambio de secreto.",
  "secrets.approvals.deletePending": "La eliminación espera aprobación de cambio de secreto.",
  "secrets.approvals.rotatedAfterApproval": "Secreto {name} rotado a la versión {version} después de la aprobación.",
  "secrets.approvals.deletedAfterApproval": "Secreto {name} eliminado después de la aprobación.",
  "secrets.cloudManagers.coverage": "{discovery} proveedores de descubrimiento, {sync} destinos de sincronización configurados",
  "secrets.cloudManagers.caption": "Cobertura de integración con gestores de secretos cloud",
  "secrets.cloudManagers.provider": "Proveedor",
  "secrets.cloudManagers.discovery": "Descubrimiento",
  "secrets.cloudManagers.sync": "Sincronización",
  "secrets.cloudManagers.handling": "Manejo",
  "secrets.cloudManagers.discoveryConfigured": "{count} fuente configurada",
  "secrets.cloudManagers.discoveryAvailable": "descubrimiento de solo lectura disponible",
  "secrets.cloudManagers.syncConfigured": "sincronización configurada",
  "secrets.cloudManagers.syncAvailable": "sincronización disponible",
  "secrets.cloudManagers.notSupported": "no soportado",
  "secrets.sync.catalogCaption": "Catálogo de proveedores de sincronización de secretos",
  "secrets.sync.configuredCount": "{count} configurados",
  "secrets.sync.target": "Destino",
  "secrets.sync.platform": "Plataforma",
  "secrets.sync.status": "Estado",
  "secrets.sync.delivery": "Entrega",
  "secrets.sync.configured": "configurado",
  "secrets.sync.available": "disponible",
  "secrets.sync.operatorCoverage": "Cobertura de sincronización y recarga del operador de Kubernetes por CRD",
  "secrets.sync.operatorCRDs": "Recursos personalizados",
  "secrets.sync.operatorReloadWorkloads": "Cargas de trabajo con recarga automática",
  "secrets.sync.injectionCoverage": "Cobertura de inyección de secretos en cargas de trabajo sin cambio de código",
  "secrets.sync.injectionCRD": "Recurso de inyección",
  "secrets.sync.injectionModes": "Modos de inyección",
  "secrets.sync.injectionWorkloads": "Cargas de trabajo inyectadas",
  "secrets.sync.unvaultedCoverage": "{findings} hallazgos filtrados, {vaults} bóvedas visibles, {sync} destinos de sincronización configurados",
  "secrets.sync.unvaultedDetection": "Fuentes de detección",
  "secrets.sync.unvaultedVaults": "Bóvedas visibles",
  "secrets.sync.unvaultedSyncTargets": "Destinos de aumento",
  "secrets.repoScan.active": "Ingreso de repositorios en tiempo real activo",
  "secrets.repoScan.unavailable": "Ingreso de repositorios no disponible",
  "secrets.repoScan.ruleFloor": "{scanner} con {rules}+ reglas requeridas",
  "secrets.repoScan.providerCaption": "Proveedores de escaneo de secretos en repositorios",
  "secrets.repoScan.provider": "Proveedor",
  "secrets.repoScan.triggers": "Disparadores",
  "secrets.repoScan.ingress": "Ingreso",
  "secrets.repoScan.outbox": "Outbox",
  "secrets.repoScan.webhookPaths": "Rutas de webhook",
  "secrets.repoScan.eventFlow": "Flujo de eventos",
  "secrets.repoScan.releaseGates": "Gates de release",
  "secrets.repoScan.residuals": "Residuales",
  "secrets.thirdPartyScan.active": "Escaneo de artefactos externos activo",
  "secrets.thirdPartyScan.unavailable": "Escaneo de artefactos externos no disponible",
  "secrets.thirdPartyScan.providerCaption": "Proveedores de escaneo de secretos externos",
  "secrets.thirdPartyScan.artifactKinds": "Tipos de artefacto",
  "secrets.thirdPartyScan.ingestPaths": "Rutas de ingreso",
  "secrets.thirdPartyScan.form": "Encolar escaneo de secretos externos",
  "secrets.thirdPartyScan.provider": "Fuente externa",
  "secrets.thirdPartyScan.source": "Referencia de origen",
  "secrets.thirdPartyScan.sourcePlaceholder": "github-actions/pagos#982",
  "secrets.thirdPartyScan.artifactPath": "Ruta del artefacto",
  "secrets.thirdPartyScan.artifactPlaceholder": "/var/lib/trstctl/exports/slack.jsonl",
  "secrets.thirdPartyScan.event": "Evento",
  "secrets.thirdPartyScan.eventPlaceholder": "workflow_run",
  "secrets.thirdPartyScan.queueing": "Encolando",
  "secrets.thirdPartyScan.queue": "Encolar escaneo",
  "secrets.thirdPartyScan.errorTitle": "Falló el escaneo externo",
  "secrets.thirdPartyScan.accepted": "Escaneo de {provider} encolado como run {run}",
  "workloads.kubernetesCSR.heading": "Controlador CertificateSigningRequest de Kubernetes",
  "workloads.kubernetesCSR.description":
    "El agente firma CSR nativas aprobadas de Kubernetes mediante la ruta configurada de emisión de trstctl y escribe solo el estado de la CSR en el clúster.",
  "workloads.kubernetesCSR.errorTitle": "Soporte de CSR de Kubernetes no disponible",
  "workloads.kubernetesCSR.errorFallback": "No se pudo cargar el soporte de CSR de Kubernetes",
  "workloads.kubernetesCSR.capability": "Capacidad",
  "workloads.kubernetesCSR.apiGroup": "Grupo API",
  "workloads.kubernetesCSR.resource": "Recurso",
  "workloads.kubernetesCSR.generated": "Generado",
  "workloads.kubernetesCSR.loading": "Cargando",
  "workloads.kubernetesCSR.signerNames": "Nombres de firmante",
  "workloads.kubernetesCSR.controllerControls": "Controles del controlador",
  "workloads.kubernetesCSR.rbac": "RBAC de Kubernetes",
  "workloads.kubernetesCSR.statusFallback": "certificatesigningrequests/status: update, patch",
  "workloads.kubernetesCSR.residuals": "Residuales",
  "workloads.trustBundles.heading": "Distribución de bundles de confianza de Kubernetes",
  "workloads.trustBundles.description":
    "El agente distribuye bundles públicos de CA en ConfigMaps de namespace desde recursos TrustBundle de alcance de clúster.",
  "workloads.trustBundles.errorTitle": "Soporte de bundle de confianza no disponible",
  "workloads.trustBundles.errorFallback": "No se pudo cargar el soporte de bundles de confianza de Kubernetes",
  "workloads.trustBundles.capability": "Capacidad",
  "workloads.trustBundles.apiGroup": "Grupo API",
  "workloads.trustBundles.resource": "Recurso",
  "workloads.trustBundles.generated": "Generado",
  "workloads.trustBundles.loading": "Cargando",
  "workloads.trustBundles.targets": "Destinos de distribución",
  "workloads.trustBundles.controllerControls": "Controles del controlador",
  "workloads.trustBundles.rbac": "RBAC de Kubernetes",
  "workloads.trustBundles.statusFallback": "trustbundles/status: update, patch",
  "workloads.trustBundles.statusFields": "Campos de estado",
  "workloads.trustBundles.residuals": "Residuales",
  "workloads.leases.heading": "Leases efimeros de credenciales",
  "workloads.leases.description":
    "Un lease es una promesa corta: una carga de trabajo demuestra quien es, recibe una clase de credencial y la pierde al expirar salvo que vuelva a atestarse.",
  "workloads.leases.timelineIssued": "00:00 emitido",
  "workloads.leases.timelineIssuedDescription": "la politica y el resumen de atestacion vinculan el lease",
  "workloads.leases.timelineRenew": "00:45 ventana de renovacion",
  "workloads.leases.timelineRenewDescription": "la carga de trabajo debe volver a atestarse antes de renovar",
  "workloads.leases.timelineExpires": "01:00 expira",
  "workloads.leases.timelineExpiresDescription": "la credencial deja de ser confiable para la politica",
  "workloads.leases.issueHeading": "Emitir lease dinamico",
  "workloads.leases.issueDescription":
    "La API devuelve solo metadatos del lease. Si un proveedor devuelve material de credencial, este panel lo mantiene fuera de la tabla del navegador.",
  "workloads.leases.provider": "Proveedor",
  "workloads.leases.role": "Rol",
  "workloads.leases.ttlSeconds": "TTL en segundos",
  "workloads.leases.issueButton": "Emitir lease",
  "workloads.leases.errorTitle": "Fallo la operacion del lease",
  "workloads.leases.leaseColumn": "Lease",
  "workloads.leases.stateColumn": "Estado",
  "workloads.leases.issuedColumn": "Emitido",
  "workloads.leases.expiresColumn": "Expira",
  "workloads.leases.actionsColumn": "Acciones",
  "workloads.leases.empty": "No se ha emitido ningun lease en esta sesion del navegador.",
  "workloads.leases.renewButton": "Renovar 5m",
  "workloads.leases.revokeButton": "Revocar",
  "workloads.leases.revokeAria": "Revocar lease {id}",
  "workloads.leases.historyUnavailableTitle": "El historial de leases aun no esta en la consola",
  "workloads.leases.historyUnavailableDescription":
    "La API de leases puede emitir, leer por ID, renovar y revocar. Una lista de leases del tenant completo aun no esta disponible en el contrato del navegador, por eso esta tabla muestra leases devueltos durante esta sesion.",
  "workloads.leases.jitUnavailableTitle": "La emision efimera JIT usa flujos externos de aprobacion",
  "workloads.leases.jitUnavailableDescription":
    "La emision efimera con aprobacion esta disponible fuera de esta consola. Esta consola no recopila payloads de prueba vivos ni acciones de aprobacion.",
  "workloads.attestation.heading": "Cadena de atestacion de carga de trabajo",
  "workloads.attestation.description":
    "La atestacion prueba la carga de trabajo y su plataforma. Envia un payload de prueba para emitir un X.509-SVID y conserva solo metadatos de atestacion en la tabla.",
  "workloads.attestation.trustSourceHeading": "Fuente de confianza de atestador",
  "workloads.attestation.trustSourceName": "Nombre de fuente de confianza",
  "workloads.attestation.trustSourceMethod": "Metodo de fuente de confianza",
  "workloads.attestation.method": "Metodo de atestacion",
  "workloads.attestation.methodKubernetesServiceAccount": "Cuenta de servicio de Kubernetes",
  "workloads.attestation.methodGithubOIDC": "GitHub OIDC",
  "workloads.attestation.methodAwsInstanceIdentity": "Identidad de instancia AWS",
  "workloads.attestation.methodAzureIMDS": "Azure IMDS",
  "workloads.attestation.methodGcpInstanceIdentity": "Identidad de instancia GCP",
  "workloads.attestation.methodTpmQuote": "Cotizacion TPM",
  "workloads.attestation.issuer": "Emisor",
  "workloads.attestation.audience": "Audiencia",
  "workloads.attestation.jwks": "JWKS JSON de fuente de confianza",
  "workloads.attestation.rootCerts": "Certificado raiz PEM de fuente de confianza",
  "workloads.attestation.expectedNonce": "Nonce esperado (base64)",
  "workloads.attestation.enabled": "Habilitada",
  "workloads.attestation.createTrustSource": "Crear fuente de confianza",
  "workloads.attestation.rotateHeading": "Rotar material de confianza",
  "workloads.attestation.trustSource": "Fuente de confianza",
  "workloads.attestation.noTrustSource": "Sin fuente de confianza",
  "workloads.attestation.rotationJwks": "JWKS JSON de rotacion",
  "workloads.attestation.rotationRootCerts": "Certificado raiz PEM de rotacion",
  "workloads.attestation.rotationNonce": "Nonce de rotacion (base64)",
  "workloads.attestation.rotationReason": "Motivo de rotacion",
  "workloads.attestation.rotateTrustSource": "Rotar fuente de confianza",
  "workloads.attestation.errorTitle": "Fallo la fuente de confianza de atestador",
  "workloads.attestation.loadErrorFallback": "No se pudieron cargar las fuentes de confianza de atestador",
  "workloads.attestation.createErrorFallback": "No se pudo crear la fuente de confianza de atestador",
  "workloads.attestation.selectToRotate": "Selecciona una fuente de confianza de atestador para rotar",
  "workloads.attestation.rotateErrorFallback": "No se pudo rotar la fuente de confianza de atestador",
  "workloads.attestation.revokeErrorFallback": "No se pudo revocar la fuente de confianza de atestador",
  "workloads.attestation.deleteErrorFallback": "No se pudo eliminar la fuente de confianza de atestador",
  "workloads.attestation.caption": "Fuentes de confianza de atestador",
  "workloads.attestation.nameColumn": "Nombre",
  "workloads.attestation.methodColumn": "Metodo",
  "workloads.attestation.statusColumn": "Estado",
  "workloads.attestation.versionColumn": "Version",
  "workloads.attestation.lastRotatedColumn": "Ultima rotacion",
  "workloads.attestation.empty": "No se ha configurado ninguna fuente de confianza de atestador.",
  "workloads.attestation.revokeButton": "Revocar",
  "workloads.attestation.offboardButton": "Retirar",
  "workloads.attestation.statusRevoked": "Revocada",
  "workloads.attestation.statusDisabled": "Deshabilitada",
  "workloads.attestation.statusEnabled": "Habilitada",
  "workloads.attestation.issueHeading": "Emitir SVID atestado",
  "workloads.attestation.issueDescription": "Los payloads de prueba y los certificados devueltos se limpian en vez de almacenarse en el estado de la UI.",
  "workloads.attestation.proofPayload": "Payload de prueba de atestacion (base64)",
  "workloads.attestation.publicKey": "Clave publica de carga de trabajo",
  "workloads.attestation.svidTTL": "TTL del SVID en segundos",
  "workloads.attestation.issueButton": "Emitir SVID atestado",
  "workloads.attestation.issueErrorTitle": "Fallo el SVID atestado",
  "workloads.attestation.issueErrorFallback": "No se pudo emitir el SVID atestado",
  "workloads.attestation.outcomesCaption": "Resultados de SVID atestados",
  "apiExplorer.title": "Explorador de API",
  "apiExplorer.description":
    "Selecciona una operación del contrato, crea una clave de prueba de corta duración, ejecuta la solicitud e inspecciona la respuesta.",
  "apiExplorer.back": "Hub de integración",
  "apiExplorer.loading": "Cargando operaciones del contrato.",
  "apiExplorer.loadFailed": "No se pudieron cargar las operaciones del contrato.",
  "apiExplorer.reload": "Recargar",
  "apiExplorer.operations": "Operaciones",
  "apiExplorer.searchLabel": "Filtrar operaciones",
  "apiExplorer.searchPlaceholder": "Filtrar por nombre o ruta",
  "apiExplorer.operationCount": "{count} operaciones",
  "apiExplorer.operationDetails": "Detalles de la operación",
  "apiExplorer.noMatches": "Ninguna operación coincide con este filtro.",
  "apiExplorer.route": "Ruta",
  "apiExplorer.operationId": "ID de operación",
  "apiExplorer.permission": "Permiso",
  "apiExplorer.required": "obligatorio",
  "apiExplorer.optional": "opcional",
  "apiExplorer.pathParameters": "Parámetros de ruta",
  "apiExplorer.queryParameters": "Parámetros de consulta",
  "apiExplorer.noParameters": "Esta solicitud no tiene parámetros obligatorios.",
  "apiExplorer.requestBody": "Cuerpo de solicitud",
  "apiExplorer.requestPreview": "Vista previa de solicitud",
  "apiExplorer.noRequestBody": "Esta solicitud no envía cuerpo.",
  "apiExplorer.examples": "Ejemplos",
  "apiExplorer.copyCurl": "Copiar curl",
  "apiExplorer.copySdk": "Copiar SDK",
  "apiExplorer.copied": "Copiado",
  "apiExplorer.runner": "Solicitud ejecutable",
  "apiExplorer.subject": "Sujeto del token",
  "apiExplorer.tokenScope": "Alcance del token",
  "apiExplorer.testKey": "Generar clave de prueba",
  "apiExplorer.generating": "Generando...",
  "apiExplorer.keyReady": "Clave de prueba con alcance lista para {scope}.",
  "apiExplorer.revealOnce": "El valor de revelación única se conserva solo en esta sesión del navegador.",
  "apiExplorer.keyFailed": "No se pudo crear una clave de prueba con alcance.",
  "apiExplorer.expires": "Expira",
  "apiExplorer.run": "Ejecutar solicitud",
  "apiExplorer.running": "Ejecutando...",
  "apiExplorer.needsKey": "Genera una clave de prueba con alcance antes de ejecutar esta solicitud.",
  "apiExplorer.response": "Respuesta",
  "apiExplorer.problemResponse": "Respuesta de problema",
  "apiExplorer.problemTitle": "Título del problema",
  "apiExplorer.problemDetail": "Detalle del problema",
  "apiExplorer.status": "Estado",
  "apiExplorer.contentType": "Tipo de contenido",
  "apiExplorer.noResponse": "Ejecuta una solicitud para ver la respuesta.",
  "apiExplorer.responseBody": "Cuerpo de respuesta",
  "apiExplorer.runFailed": "Falló la ejecución de la solicitud.",
  "integrate.title": "Integrar",
  "integrate.description":
    "Conecta trstctl con tu stack: protocolos de enrolamiento, SDKs de lenguaje e infraestructura como codigo, cada uno con una referencia copiable.",
  "integrate.copy.copy": "Copiar",
  "integrate.copy.copied": "Copiado",
  "integrate.copy.value": "Copiar {value}",
  "integrate.protocols.title": "Protocolos de enrolamiento",
  "integrate.protocols.description": "Endpoints estandarizados de enrolamiento de certificados (por perfil de emision).",
  "integrate.sdks.title": "SDKs",
  "integrate.sdks.description": "Bibliotecas cliente generadas para la API de trstctl.",
  "integrate.gitops.title": "Flujo GitOps",
  "integrate.gitops.description": "Genera declaraciones desde el estado vivo, validalas con dry-run de politicas y compara campos vivos contra declarados.",
  "integrate.gitops.loadUnavailable": "Estado vivo de GitOps no disponible",
  "integrate.gitops.manifest.profile": "Perfil de emision",
  "integrate.gitops.manifest.discoverySource": "Fuente de descubrimiento",
  "integrate.gitops.manifest.routingPolicy": "Politica de enrutamiento de notificaciones",
  "integrate.gitops.manifest.installValues": "Valores de instalacion",
  "integrate.gitops.manifestType": "Tipo de manifiesto",
  "integrate.gitops.liveObject": "Objeto vivo",
  "integrate.gitops.loading": "Cargando fuentes GitOps...",
  "integrate.gitops.declarativeManifest": "Manifiesto declarativo",
  "integrate.gitops.validateDeclaration": "Validar declaracion",
  "integrate.gitops.validating": "Validando",
  "integrate.gitops.copyDeclaration": "Copiar declaracion",
  "integrate.gitops.exportDeclaration": "Exportar declaracion",
  "integrate.gitops.openApiExplorer": "Abrir en el explorador de API",
  "integrate.gitops.validationResult": "Resultado de validacion GitOps",
  "integrate.gitops.valid": "Valido",
  "integrate.gitops.invalid": "Invalido",
  "integrate.gitops.decision": "Decision",
  "integrate.gitops.moduleDigest": "Digest del modulo",
  "integrate.gitops.query": "Consulta",
  "integrate.gitops.idempotency": "Idempotencia",
  "integrate.gitops.driftComparison": "Comparacion de drift GitOps",
  "integrate.gitops.path": "Ruta",
  "integrate.gitops.live": "Vivo",
  "integrate.gitops.declared": "Declarado",
  "integrate.gitops.status": "Estado",
  "integrate.gitops.noComparableDeclaration": "No hay una declaracion comparable cargada.",
  "integrate.gitops.driftSummary": "{count} drift {fields}",
  "integrate.gitops.fieldSingular": "campo",
  "integrate.gitops.fieldPlural": "campos",
  "integrate.iac.title": "Infraestructura como codigo",
  "integrate.iac.description": "Declara la confianza de trstctl de la misma forma que declaras el resto de tu plataforma.",
  "privacy.title": "Privacidad y gobierno de datos",
  "privacy.description":
    "Controles de privacidad y GDPR: inventaria los tipos de datos personales que conservas, atiende solicitudes de borrado y aplica calendarios de retencion.",
  "privacy.loading": "Cargando postura de privacidad...",
  "privacy.stats.catalogEntries": "Entradas del catalogo",
  "privacy.stats.subjectErasures": "Borrados de sujeto",
  "privacy.stats.retentionRuns": "Ejecuciones de retencion",
  "privacy.error.actionFailed": "Fallo la accion de privacidad",
  "privacy.erasure.title": "Borrado de sujeto",
  "privacy.erasure.description": "Derecho al olvido: borra cada credencial y registro vinculado a un sujeto de datos.",
  "privacy.erasure.subjectLabel": "Sujeto de datos",
  "privacy.subjectPlaceholder": "id de propietario, correo o ref de sujeto",
  "privacy.erasure.reasonLabel": "Motivo",
  "privacy.erasure.reasonPlaceholder": "opcional - registrado en el borrado",
  "privacy.erasure.busy": "Borrando...",
  "privacy.erasure.submit": "Borrar sujeto",
  "privacy.erasure.empty": "Aun no hay borrados de sujeto registrados.",
  "privacy.erasure.tableCaption": "Borrados de sujeto recientes",
  "privacy.subjectColumn": "Sujeto",
  "privacy.erasure.recordsErasedColumn": "Registros borrados",
  "privacy.erasure.erasedAtColumn": "Borrado el",
  "privacy.export.title": "Exportacion de sujeto",
  "privacy.export.description": "Flujo de acceso y portabilidad para cada registro catalogado vinculado a un sujeto de datos.",
  "privacy.export.subjectLabel": "Exportar sujeto de datos",
  "privacy.export.busy": "Exportando...",
  "privacy.export.submit": "Exportar sujeto",
  "privacy.export.failed": "Fallo la exportacion del sujeto",
  "privacy.export.subjectRef": "Ref de sujeto",
  "privacy.export.generated": "Generado",
  "privacy.export.countsCaption": "Conteos de exportacion de sujeto",
  "privacy.export.recordClassColumn": "Clase de registro",
  "privacy.export.countColumn": "Conteo",
  "privacy.export.summary": "Se exportaron {count} referencias de registros catalogados. Los secretos y el material de tokens no se muestran.",
  "privacy.retention.title": "Aplicacion de retencion",
  "privacy.retention.description": "Aplica la politica de retencion en credenciales, propietarios, agentes y evidencia; cada ejecucion registra sus cortes.",
  "privacy.retention.busy": "Aplicando...",
  "privacy.retention.submit": "Aplicar retencion ahora",
  "privacy.retention.empty": "Aun no hay ejecuciones de retencion registradas.",
  "privacy.retention.tableCaption": "Ejecuciones de retencion",
  "privacy.retention.runColumn": "Ejecucion",
  "privacy.retention.recordsAffectedColumn": "Registros afectados",
  "privacy.retention.requestedByColumn": "Solicitado por",
  "privacy.retention.enforcedAtColumn": "Aplicado el",
  "privacy.catalog.title": "Catalogo de datos personales",
  "privacy.catalog.description": "Que datos personales viven donde, quien los posee, por que se conservan y como se borran.",
  "privacy.catalog.empty": "No se devolvieron entradas de catalogo.",
  "privacy.catalog.categoryColumn": "Categoria",
  "privacy.catalog.locationColumn": "Ubicacion",
  "privacy.catalog.ownerColumn": "Propietario",
  "privacy.catalog.purposeColumn": "Proposito",
  "privacy.catalog.retentionColumn": "Retencion",
  "parity.airGap_a0134a": "Aislamiento de red",
  "parity.allowWildcardIssuance_0fe53c": "Permitir emisión de comodín",
  "parity.allowedMethods_ac5c6c": "Métodos permitidos",
  "parity.applyIdentityFilter_72d5ba": "Aplicar filtro de identidad",
  "parity.approveEphemeralCredential_760861": "Aprobar credencial efímera",
  "parity.approversCanIssueThisFromThe_33b073": "Los aprobadores pueden emitirla desde la página de Aprobaciones.",
  "parity.archiveAttestationRequestFailed_6179ba": "Error al registrar la atestación de archivo",
  "parity.archiveErasureAttestationRecorded_4e1490": "Atestación de borrado de archivo registrada",
  "parity.archiveErasureEvidence_9a62ca": "Evidencia de borrado de archivo",
  "parity.artifactUri_2088cf": "URI del artefacto",
  "parity.attestationGatedCredentials_2887bd": "Credenciales con atestación",
  "parity.attestationPayloadBase64_b7cf3a": "Carga de atestación (base64)",
  "parity.backup_89121d": "backup",
  "parity.brokerEvidenceForThisJustIn_44ca48": "Evidencia intermediada de esta sesión de acceso puntual, incluidos registros de atestación y auditoría.",
  "parity.builtInGuarantees_21db16": "Garantías integradas",
  "parity.caaIssuerDomainOptional_8c2f53": "Dominio emisor CAA (opcional)",
  "parity.captureEvidenceOfHowABackup_f00d4e":
    "Registra la evidencia de cómo una copia de seguridad o un archivo de auditoría firmado respetó el borrado de un sujeto.",
  "parity.ceremonyDetail_9cb326": "Detalle de ceremonia",
  "parity.ceremonyId_6f8ee6": "ID de ceremonia",
  "parity.certifiesAnExternallyHeldIntermediateKey_d95cc4":
    "Certifica una clave intermedia externa bajo esta autoridad mediante una ceremonia aprobada por quórum.",
  "parity.challengeDomainOptional_d7bed2": "Dominio de desafío (opcional)",
  "parity.challengeMode_1c8fbd": "Modo de desafío",
  "parity.challengeRecord_320513": "Registro de desafío",
  "parity.challengeRotationFailed_c4b11e": "Error en la rotación del desafío",
  "parity.clearIdentityFilter_3c0b9a": "Borrar filtro de identidad",
  "parity.closeAuthorityDetail_9bee0e": "Cerrar detalle de autoridad",
  "parity.closeCeremonyDetail_92fb97": "Cerrar detalle de ceremonia",
  "parity.closeCreateCaForm_e01a8e": "Cerrar formulario de creación de CA",
  "parity.closeDns01ConfigForm_00c6cb": "Cerrar formulario de configuración DNS-01",
  "parity.closeIssueLeafForm_2c9eeb": "Cerrar formulario de emisión de hoja",
  "parity.closePreflightDialog_97a0fb": "Cerrar diálogo de comprobación previa",
  "parity.closeScepPolicyForm_ae9570": "Cerrar formulario de política SCEP",
  "parity.closeSignIntermediateCsrForm_162507": "Cerrar formulario de firma de CSR intermedia",
  "parity.commonNameMaxPathLenSignature_0d8b25": "common_name, max_path_len, signature_algorithm, ttl_seconds",
  "parity.configName_11f179": "Nombre de configuración",
  "parity.controlPlaneLineage_513399": "Linaje del plano de control",
  "parity.copied_dd2ce2": "Copiado.",
  "parity.copyCertificate_59db8a": "Copiar certificado",
  "parity.copyRequestId_a53908": "Copiar ID de solicitud",
  "parity.couldNotRecordAttestation_204858": "No se pudo registrar la atestación",
  "parity.createIntermediateCa_829ab7": "Crear CA intermedia",
  "parity.createRootCa_94fb33": "Crear CA raíz",
  "parity.createRotationSchedule_6a80bd": "Crear programación de rotación",
  "parity.credentialReferencesJsonOptional_faddae": "JSON de referencias de credenciales (opcional)",
  "parity.cryptoAgilityMeansTheSystemCan_20c325":
    "La cripto-agilidad significa que el sistema puede ver algoritmos débiles, rechazar opciones no permitidas y planificar rotaciones seguras sin adivinar desde el estado del navegador.",
  "parity.cryptographicShred_caafb7": "triturado criptográfico",
  "parity.csrPem_c5931f": "CSR en PEM",
  "parity.delegationTargetOptional_8439dd": "Destino de delegación (opcional)",
  "parity.deleteOwner_b5f9bd": "Eliminar propietario",
  "parity.delete_f6fdbe": "Eliminar",
  "parity.deleted_b639f5": "eliminado",
  "parity.deletingAnOwnerRemovesTheAccountability_cdfad5":
    "Eliminar un propietario borra el registro de responsabilidad de sus credenciales. Esto no se puede deshacer.",
  "parity.details_dc3dec": "Detalles",
  "parity.distributionPosture_10c8b4": "Postura de distribución",
  "parity.dns01ConfigUpdateFailed_86ad97": "Error al actualizar la configuración DNS-01",
  "parity.dns01ProviderConfigDeleted_9ead6a": "Configuración de proveedor DNS-01 eliminada",
  "parity.dns01ProviderConfigUpdated_5a6d3d": "Configuración de proveedor DNS-01 actualizada",
  "parity.domain_9b1091": "Dominio",
  "parity.editConnectorTarget_6063fb": "Editar destino de conector",
  "parity.edit_530164": "Editar",
  "parity.emailOptional_5c10b5": "Correo electrónico (opcional)",
  "parity.ephemeralCredentialApprovals_9a4b68": "Aprobaciones de credenciales efímeras",
  "parity.ephemeralCredentialRequestFailed_12be63": "Error en la solicitud de credencial efímera",
  "parity.eventSourcedRemediationRunEvidenceIncluding_cec725":
    "Evidencia de ejecución de remediación basada en eventos, incluido el recibo de entrega del conector cuando se registró.",
  "parity.evidenceReferencesOnePerLine_2bb536": "Referencias de evidencia (una por línea)",
  "parity.expectedAudienceOptional_51c8b7": "Audiencia esperada (opcional)",
  "parity.expectedTxtValueOptional_c4e94f": "Valor TXT esperado (opcional)",
  "parity.failedPhase_49b14a": "Fase fallida:",
  "parity.failures_3eec15": "Fallos",
  "parity.filterRotationRuns_e652a6": "Filtrar ejecuciones de rotación",
  "parity.fingerprintOptional_b6cd87": "Huella digital (opcional)",
  "parity.firstRunOptional_7ecf76": "Primera ejecución (opcional)",
  "parity.fullConnectorDeliveryReceiptEvidenceIncluding_080df5":
    "Evidencia completa del recibo de entrega del conector, incluida la referencia de reversión y el motivo del fallo.",
  "parity.fullLifecycleRotationRunRecordIncluding_02687f":
    "Registro completo de la ejecución de rotación del ciclo de vida, incluidas huellas, referencia de reversión y evidencia de errores.",
  "parity.heldUntil_8cc7d7": "Retenido hasta",
  "parity.hmacDynamic_cb11c5": "hmac-dynamic",
  "parity.iUnderstandThisRevocationCannotBe_92d164": "Entiendo que esta revocación no se puede deshacer.",
  "parity.identityIdFilter_48db11": "Filtro de ID de identidad",
  "parity.identityUuid_209e1d": "UUID de identidad",
  "parity.intermediateCsrSigningFailed_636cae": "Error al firmar la CSR intermedia",
  "parity.intuneJws_b47f57": "intune-jws",
  "parity.intune_2c4886": "intune",
  "parity.issueLeafCertificate_bddf5d": "Emitir certificado de hoja",
  "parity.issueLeaf_f1c3ee": "Emitir hoja…",
  "parity.jamf_489375": "jamf",
  "parity.justInTimeOperatorSessionsBrokered_df233f": "Sesiones de operador puntuales intermediadas para roles de PostgreSQL y entidades SSH.",
  "parity.lastError_5e4df8": "Último error",
  "parity.latestDueRotationRuns_ac4710": "Últimas ejecuciones de rotación vencidas",
  "parity.leafIssuanceFailed_235d03": "Error en la emisión de hoja",
  "parity.legalHold_644327": "retención legal",
  "parity.lifecycleRotationEvidenceWhoRotatedWhat_10ed9a": "Evidencia de rotación del ciclo de vida: quién rotó qué, cuándo y cómo terminó.",
  "parity.methodOverrideOptional_154ad0": "Anulación de opción (opcional)",
  "parity.newRotationSchedule_0d2b93": "Nueva programación de rotación",
  "parity.newSchedule_729465": "Nueva programación…",
  "parity.noOutboxCircuitBreakers_b8a7be": "Sin interruptores de circuito de bandeja de salida",
  "parity.noOutboxDestinationHasRecordedCircuit_1c248f": "Ningún destino de bandeja de salida ha registrado estado de circuito todavía.",
  "parity.noOwnerRemediationActionsAreQueued_596b9b": "No hay acciones de remediación de propietario en cola.",
  "parity.observedTxtRecordsOptionalOnePer_9b6c49": "Registros TXT observados (opcional, uno por línea)",
  "parity.oldReference_69d1f6": "Referencia anterior",
  "parity.openPrivilegedSession_78a445": "Abrir sesión privilegiada",
  "parity.openSession_73b3ca": "Abrir sesión…",
  "parity.openUntil_5c3e00": "Abierto hasta",
  "parity.optionalEGS3Backups2026_891da1": "opcional, p. ej. s3://backups/2026-06-30.tar.zst",
  "parity.outboxCircuitBreakers_278ec6": "Interruptores de circuito de bandeja de salida",
  "parity.ownerDeleted_079d61": "Propietario eliminado",
  "parity.ownerRemediationQueue_610e16": "Cola de remediación de propietarios",
  "parity.ownerUpdated_07b92f": "Propietario actualizado",
  "parity.ownership_3e90e4": "Propiedad",
  "parity.parentAuthority_d9bb89": "Autoridad principal",
  "parity.parseError_387dc4": "error de análisis",
  "parity.payloadBase64_738cc4": "Carga (base64)",
  "parity.paymentsDbMonthly_b690bc": "payments-db-monthly",
  "parity.paymentsDbPassword_50e8d6": "payments/db/password",
  "parity.playbookRunHistoryUnavailable_8452d8": "Historial de ejecuciones de playbook no disponible",
  "parity.playbookRuns_da379d": "Ejecuciones de playbook",
  "parity.policyDefault_38146c": "Predeterminado de política",
  "parity.policyName_101bf6": "Nombre de política",
  "parity.postgres_afc848": "postgres",
  "parity.postgresql_519968": "postgresql",
  "parity.preflightCheck_4a464a": "Comprobación previa…",
  "parity.preflightRequestFailed_69f031": "Error en la comprobación previa",
  "parity.privilegedAccessSessions_368da5": "Sesiones de acceso privilegiado",
  "parity.productionMode_1737a4": "Modo de producción",
  "parity.profileGuidanceJsonOptional_fd4738": "JSON de guía de perfil (opcional)",
  "parity.providerConfigJsonOptional_02753c": "JSON de configuración del proveedor (opcional)",
  "parity.providerDefault_f75bf4": "Predeterminado del proveedor",
  "parity.publicKeyPem_10749e": "Clave pública (PEM)",
  "parity.quorumApprovedCeremonyId_df8e12": "id de ceremonia aprobada por quórum",
  "parity.recordedPlaybookRunsWithTheirConnector_bffffe":
    "Ejecuciones de playbook registradas con sus recibos de entrega del conector y una instantánea de la cola de remediación de propietarios.",
  "parity.recurringRollbackSafeRotationsRunBy_06c343":
    "Rotaciones recurrentes con reversión segura ejecutadas por el programador. «Ejecutar vencidas» ejecuta cada programación habilitada cuya próxima ejecución ya está vencida.",
  "parity.remediationEvidence_5174c6": "Evidencia de remediación",
  "parity.remoteKeyOptional_b6dff8": "Clave remota (opcional)",
  "parity.req7c2f9a_03dd4e": "req-7c2f9a",
  "parity.requestAttestationGatedEphemeralCredential_4ce3ce": "Solicitar credencial efímera con atestación",
  "parity.requestId_63aa59": "ID de solicitud",
  "parity.revokeCertificate_338ad7": "Revocar certificado",
  "parity.rollbackSafeRotationFailed_5f1a57": "Error en la rotación con reversión segura",
  "parity.rollbackSafeRotation_267d4a": "Rotación con reversión segura",
  "parity.rotateAProviderBackedCredentialBy_ec7a8f":
    "Rota una credencial respaldada por un proveedor mediante referencia. Si una fase falla, la ejecución revierte a la referencia anterior y el resultado a continuación informa el resultado exacto. Ningún valor secreto pasa por este formulario.",
  "parity.rotateChallenge_99fc02": "Rotar desafío",
  "parity.rotationMintsFreshChallengeMaterialAnd_0aec47":
    "La rotación genera material de desafío nuevo y registra evidencia de rotación: la versión de rotación se incrementa y la marca de tiempo se conserva para auditoría. Los perfiles que distribuyen el desafío anterior dejan de validar nuevas inscripciones.",
  "parity.rotationRuns_5ec15c": "Ejecuciones de rotación",
  "parity.routing_7d15dd": "Enrutamiento",
  "parity.runDueRotationsFailed_b9c511": "Error al ejecutar rotaciones vencidas",
  "parity.runModes_6fced8": "Modos de ejecución",
  "parity.runRollbackSafeRotation_5a7f2d": "Ejecutar rotación con reversión segura",
  "parity.saveConfig_64e1de": "Guardar configuración",
  "parity.saveOwner_b67638": "Guardar propietario",
  "parity.savePolicy_77d67c": "Guardar política",
  "parity.saveTarget_fa5df1": "Guardar destino",
  "parity.scepChallengeRotated_77c4f1": "Desafío SCEP rotado",
  "parity.scepEndpoint_f4bb21": "Punto de conexión SCEP",
  "parity.scepPolicyDeleted_45064c": "Política SCEP eliminada",
  "parity.scepPolicyUpdateFailed_f92dc7": "Error al actualizar la política SCEP",
  "parity.scepPolicyUpdated_3a2953": "Política SCEP actualizada",
  "parity.scepProfile_315862": "Perfil SCEP",
  "parity.scheduleName_fb63dc": "Nombre de la programación",
  "parity.scheduledRotations_1a0452": "Rotaciones programadas",
  "parity.secretReferencesOnlyRawCredentialsAre_f74f29": "Solo referencias de secretos: las credenciales sin procesar nunca se almacenan en la configuración.",
  "parity.selectParentAuthority_76a0a6": "Seleccionar autoridad principal",
  "parity.selectedMethod_9ad9ca": "Opción seleccionada",
  "parity.serialOptional_e59169": "Número de serie (opcional)",
  "parity.servedAuthorities_52df47": "Autoridades disponibles",
  "parity.sessionOpened_368838": "Sesión abierta.",
  "parity.signIntermediateCsr_cf1361": "Firmar CSR intermedia…",
  "parity.signIntermediateCsr_e1f90b": "Firmar CSR intermedia",
  "parity.signedAuditArchive_753384": "archivo de auditoría firmado",
  "parity.signerBackedRootsAndIntermediatesThis_957f38":
    "Raíces e intermedias respaldadas por el firmante que sirve este plano de control. Abra una fila para ver el PEM del certificado, emitir una hoja desde una autoridad o firmar una CSR intermedia generada externamente.",
  "parity.specJson_e57c5c": "JSON de especificación",
  "parity.sshPrincipal_8d0a6c": "Entidad SSH",
  "parity.ssh_e8b9f6": "ssh",
  "parity.subjectFilter_ae9f99": "Filtro de sujeto",
  "parity.supportedHostArchives_38c6c0": "Archivos de host compatibles",
  "parity.syncTargetOptional_189fc7": "Destino de sincronización (opcional)",
  "parity.targetConfigJson_68839a": "JSON de configuración del destino",
  "parity.targetConnector_99a265": "Conector del destino",
  "parity.targetId_00960a": "ID de destino",
  "parity.targetName_f2f724": "Nombre del destino",
  "parity.targetType_a45f80": "Tipo de destino",
  "parity.theCbomScannerInventoriesAlgorithmsKey_777219":
    "El escáner CBOM inventaría algoritmos, tamaños de clave, versiones de TLS y posturas criptográficas débiles. El mínimo de política es RSA-2048, EC-256 y TLS 1.2, mientras que 3DES/DES/RC4/NULL/EXPORT/MD5 están prohibidos.",
  "parity.theProviderWasRolledBackCleanly_3c888a": "El proveedor se revirtió limpiamente a",
  "pqc.readiness.aria": "Preparación para migración PQC",
  "pqc.readiness.migrated": "{percent}% migrado",
  "pqc.readiness.totalAssets": "Activos totales",
  "pqc.readiness.quantumVulnerable": "Activos vulnerables a computación cuántica",
  "pqc.readiness.readyAssets": "Activos listos para PQC",
  "parity.theServedContractRequiresASpec_bf854f": "La emisión intermedia requiere una especificación (common_name, longitud de ruta, TTL).",
  "parity.tpmQuote_f72300": "tpm-quote",
  "parity.trustAnchorReferencesJsonOptional_f5ea80": "JSON de referencias de anclas de confianza (opcional)",
  "parity.ttlSecondsOptional_68f1c5": "Segundos de TTL (opcional)",
  "parity.typeConfigNameToConfirm_f46ed6": "Escriba el nombre de la configuración para confirmar",
  "parity.typePolicyNameToConfirm_fc5738": "Escriba el nombre de la política para confirmar",
  "parity.typeTargetNameToConfirm_aedaad": "Escriba el nombre del destino para confirmar",
  "parity.typeTheExactOwnerName_1205b0": "Escriba el nombre exacto del propietario",
  "parity.updateTheConnectorTargetNameConnector_1dafe2":
    "Actualice el nombre del destino del conector, el conector y el JSON de configuración, luego guarde para aplicar el cambio.",
  "parity.validatesDelegationTxtPropagationCaaPolicy_1ceb4c":
    "Valida la delegación, la propagación TXT, la política CAA y la selección de la opción de desafío de un dominio antes de emitir una orden ACME.",
  "parity.view_69bd4e": "Ver",
  "parity.wildcard_08654e": "comodín",
  "parity.yesDeleteConfig_bd6fac": "Sí, eliminar configuración",
  "parity.yesDeletePolicy_30ce34": "Sí, eliminar política",
  "parity.yesDeleteTarget_729269": "Sí, eliminar destino",
  "parity.zoneOptional_0f915d": "Zona (opcional)",
} satisfies Record<MessageKey, string>;

function buildCatalog(localize: (message: string) => string): Record<MessageKey, string> {
  return Object.fromEntries(Object.entries(messages).map(([key, descriptor]) => [key, localize(descriptor.defaultMessage)])) as Record<MessageKey, string>;
}

export const catalogs: Record<Locale, Record<MessageKey, string>> = {
  "en-US": buildCatalog((message) => message),
  "es-ES": esESCatalog,
  "en-XA": buildCatalog(pseudoLocalize),
  "ar-XB": buildCatalog(pseudoLocalize),
};
