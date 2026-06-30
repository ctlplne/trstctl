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
    defaultMessage: "The lease API can issue, read by ID, renew, and revoke. A tenant-wide lease list is not available in the browser contract yet, so this table shows leases returned during this session.",
    description: "Unavailable-state description for tenant-wide lease history.",
  },
  "workloads.leases.jitUnavailableTitle": {
    defaultMessage: "Ephemeral JIT issuance uses external approval flows",
    description: "Unavailable-state title for ephemeral JIT issuance approvals.",
  },
  "workloads.leases.jitUnavailableDescription": {
    defaultMessage: "Approval-gated ephemeral issuance is available outside this console. This console does not collect live proof payloads or approval actions.",
    description: "Unavailable-state description for ephemeral JIT issuance approvals.",
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
  "discovery.findings.detailHeading": "Detalle del hallazgo",
  "discovery.findings.close": "Cerrar",
  "discovery.findings.triageReason": "Motivo",
  "discovery.findings.managedIdentity": "Identidad administrada",
  "discovery.findings.claimSubmit": "Reclamar como administrado",
  "discovery.findings.dismissSubmit": "Descartar hallazgo",
  "discovery.findings.claimError": "No se pudo reclamar el hallazgo de descubrimiento",
  "discovery.findings.dismissError": "No se pudo descartar el hallazgo de descubrimiento",
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
