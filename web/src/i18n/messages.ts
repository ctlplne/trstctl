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
    defaultMessage: "dual-control issue and revoke inbox",
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
  "nav.item.privacy": {
    defaultMessage: "Privacy",
    description: "Primary navigation item.",
  },
  "nav.item.integrate": {
    defaultMessage: "Integration & SDKs",
    description: "Primary navigation item.",
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
  "connectors.deliveryEvidence": {
    defaultMessage: "Connector delivery evidence",
    description: "Heading for served connector registry and delivery receipt evidence.",
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
  "nav.task.pendingApprovals.description": "bandeja de emisión y revocación con doble control",
  "nav.task.highestRisk.label": "Mayor riesgo",
  "nav.task.highestRisk.description": "lista de rotación priorizada por riesgo",
  "certificates.health.heading": "Salud de certificados del entorno",
  "certificates.health.description": "Incluye inventario de certificados emitidos, importados y descubiertos.",
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
  "caHierarchy.discovery.description": "Las CA ascendentes públicas, las CA ascendentes privadas y las autoridades importadas de la jerarquía de CA se normalizan en un inventario de solo lectura.",
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
  "caHierarchy.offline.heading": "Raíz sin conexión",
  "caHierarchy.offline.description": "Importa una raíz pública, genera una CSR de intermediaria retenida por el firmante e importa la intermediaria firmada por la raíz.",
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
  "caHierarchy.existing.description": "Vincula una cadena de certificados raíz o intermedia ya existente a un identificador de clave retenido por el firmante después de una revisión m-de-n.",
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
  "nav.item.incidents": "Incidentes",
  "nav.item.approvals": "Aprobaciones",
  "nav.item.audit": "Auditoría",
  "nav.item.ownership": "Propiedad",
  "nav.item.rbac": "RBAC",
  "nav.item.policy": "Política",
  "policy.framework.cabfBR": "BR del Foro CA/B",
  "policy.framework.fips140": "FIPS 140",
  "policy.framework.commonCriteria": "Criterios comunes",
  "nav.item.privacy": "Privacidad",
  "nav.item.integrate": "Integración y SDK",
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
  "risk.nhiStale.summary": "CAP-POST-02: {findings} obsoletas, sin uso, huérfanas o dormidas de {total} NHI analizadas; {dormant} dormidas, {orphaned} huérfanas.",
  "risk.nhiStale.loading": "Cargando postura de NHI obsoletas.",
  "risk.nhiStale.unavailableTitle": "Postura de NHI obsoletas no disponible",
  "risk.nhiStale.empty": "No se detectó evidencia de NHI obsoletas, sin uso, huérfanas o dormidas.",
  "risk.nhiStale.caption": "Recomendaciones para NHI obsoletas y dormidas",
  "risk.nhiStale.nhi": "NHI",
  "risk.nhiStale.finding": "Hallazgo",
  "risk.nhiStale.age": "Antigüedad",
  "risk.nhiStale.ageValue": "{activity}d actividad / {created}d creada",
  "risk.nhiStale.recommendation": "Recomendación",
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
  "connectors.deliveryEvidence": "Evidencia de entrega del conector",
  "protocols.dns01.heading": "Proveedores DNS-01",
  "protocols.dns01.caption": "Cobertura de proveedores DNS-01 de ACME",
  "protocols.dns01.provider": "Proveedor",
  "protocols.dns01.kind": "Tipo",
  "protocols.dns01.conformance": "Conformidad",
  "protocols.dns01.secretReferences": "Referencias de secretos",
  "protocols.dns01.capabilityGrant": "Permiso de capacidad",
  "protocols.dns01.propagationPreflight": "Preflight de propagación",
  "protocols.dns01.noRawSecretFields": "Sin campos de secreto sin procesar",
  "protocols.dns01.loading": "Cargando cobertura de proveedores DNS-01.",
  "protocols.dns01.unavailableTitle": "Proveedores DNS-01 no disponibles",
  "protocols.dns01.empty": "No se devolvieron filas del catálogo de proveedores.",
  "protocols.dns01.served": "Disponible",
  "protocols.dns01.off": "Desactivado",
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
