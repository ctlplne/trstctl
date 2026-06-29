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
  "policy.reportType.inventorySnapshot": "Instantánea de inventario",
  "policy.reportType.frameworkEvidencePack": "Paquete de evidencia del marco",
  "policy.reportType.cbomPosture": "Postura CBOM",
  "policy.reportType.auditSummary": "Resumen de auditoría",
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
  "incidents.playbooks.heading": "Playbooks de remediación automatizada",
  "incidents.playbooks.description": "Ejecuta playbooks de revocación, rotación y ajuste de permisos con evidencia auditable y acciones externas en cola.",
  "incidents.playbooks.targetIdentity": "Identidad objetivo",
  "incidents.playbooks.inventoryId": "ID de inventario",
  "incidents.playbooks.connector": "Método de entrega del playbook",
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
