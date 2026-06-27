export const defaultLocale = "en-US";
export const defaultTimeZone = "UTC";
export const supportedLocales = ["en-US", "en-XA", "ar-XB"] as const;

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
    defaultMessage: "Profiles",
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
    defaultMessage: "Connectors",
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
    defaultMessage: "Posture",
    description: "Primary navigation item.",
  },
  "nav.item.graph": {
    defaultMessage: "Graph",
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
  "nav.item.privacy": {
    defaultMessage: "Privacy",
    description: "Primary navigation item.",
  },
  "nav.item.integrate": {
    defaultMessage: "Integrate",
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
} as const;

export type MessageKey = keyof typeof messages;

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

function buildCatalog(localize: (message: string) => string): Record<MessageKey, string> {
  return Object.fromEntries(Object.entries(messages).map(([key, descriptor]) => [key, localize(descriptor.defaultMessage)])) as Record<MessageKey, string>;
}

export const catalogs: Record<Locale, Record<MessageKey, string>> = {
  "en-US": buildCatalog((message) => message),
  "en-XA": buildCatalog(pseudoLocalize),
  "ar-XB": buildCatalog(pseudoLocalize),
};
