// Demo dashboard data — used ONLY in dev/preview mode (preview@trstctl.local) so the
// console looks alive when no backend is serving real data. Mirrors the values in the
// clarity.html prototype. Never used when a real session/backend is present.

export interface DemoActivity {
  action: string;
  detail: string;
  result: "ok" | "retry" | "denied";
  ts: string;
}

export const demoDashboard = {
  kpis: {
    certificates: 1284,
    identities: 3471,
    secrets: 612,
    agentsOnline: 46,
    agentsTotal: 48,
    expiring7d: 9,
    highRisk: 14,
    openIncidents: 2,
    pqcReady: 34,
  },
  deltas: { certificates: "+12%", identities: "+8%", secrets: "+3%", pqcReady: "+PQC" },
  // ~12 weeks of credentials issued per month.
  issuanceTrend: [42, 51, 38, 61, 73, 58, 66, 80, 72, 91, 84, 97],
  expiryBands: [
    { label: "<7d", n: 9, tone: "crit" as const },
    { label: "7–30d", n: 54, tone: "warn" as const },
    { label: "30–90d", n: 188, tone: "ok" as const },
    { label: ">90d", n: 1033, tone: "ok" as const },
  ],
  algoMix: [
    { algo: "ECDSA P-256", n: 742 },
    { algo: "RSA-2048", n: 368 },
    { algo: "RSA-4096", n: 131 },
    { algo: "Ed25519", n: 33 },
    { algo: "Ed25519", n: 10 },
  ],
  rotateFirst: [
    { subject: "legacy-gw.acme.io", detail: "expires <48h · RSA-2048", score: 94 },
    { subject: "legacy-cron (orphaned)", detail: "no owner · no rotation 400d+", score: 89 },
    { subject: "db-primary.internal", detail: "expires <72h · high blast-radius", score: 81 },
    { subject: "old-intranet.acme.io", detail: "revoked but still deployed", score: 77 },
    { subject: "stripe/live/secret", detail: "rotation 61d > policy 30d", score: 72 },
  ],
  recentActivity: [
    { action: "identity.transition", detail: "nhi_a1 → issued", result: "ok", ts: "14:22" },
    { action: "cert.deploy", detail: "crt_8f21 → nginx ip-10-2-3-11", result: "ok", ts: "14:09" },
    { action: "risk.rescore", detail: "1284 credentials", result: "ok", ts: "13:47" },
    { action: "jit.approve", detail: "req_5521 (ssh deploy-bot)", result: "ok", ts: "13:31" },
    { action: "outbox.deliver", detail: "webhook slack/alerts", result: "retry", ts: "12:58" },
    { action: "cert.revoke", detail: "crt_9a44 (keyCompromise)", result: "ok", ts: "12:40" },
  ] as DemoActivity[],
};
