import { useState } from "react";
import { AreaTrend, BucketBar, Donut, Meter, Sparkline, StatTile, chartToneColor, type ChartTone } from "@/components/charts";
import { CredentialChip } from "@/components/CredentialChip";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader } from "@/components/PageHeader";
import { Eyebrow, Num } from "@/components/typography";
import { PageTabs, tabPanelProps } from "@/components/PageTabs";
import { ErrorState, LoadingState, PermissionDeniedState, UnavailableState } from "@/components/StatePrimitives";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

/** Styleguide is the living spec for the trstctl design language: every token
 * and primitive rendered from the real implementation, so what this page shows
 * is — by construction — what ships. The palette, type, and components are
 * adapted from trstctl.com into a quiet operator surface: light-first neutral
 * space, one forest action channel, mint focus, Sora UI copy, DM Mono machine
 * data, and Syne only for the wordmark. See web/DESIGN.md for the rules. */

const colorTokens: Array<{ group: string; tokens: Array<{ name: string; className: string }> }> = [
  {
    group: "Brand",
    tokens: [
      { name: "primary (forest)", className: "bg-primary" },
      { name: "brand-accent", className: "bg-brand-accent" },
      { name: "sidebar rail", className: "bg-sidebar" },
    ],
  },
  {
    group: "Surfaces",
    tokens: [
      { name: "background", className: "bg-background border border-border" },
      { name: "card", className: "bg-card border border-border" },
      { name: "muted", className: "bg-muted" },
    ],
  },
  {
    group: "Risk",
    tokens: [
      { name: "critical", className: "bg-risk-critical" },
      { name: "high", className: "bg-risk-high" },
      { name: "medium", className: "bg-risk-medium" },
      { name: "low", className: "bg-risk-low" },
      { name: "none", className: "bg-risk-none" },
    ],
  },
  {
    group: "Status",
    tokens: [
      { name: "success", className: "bg-status-success" },
      { name: "warning", className: "bg-status-warning" },
      { name: "info", className: "bg-status-info" },
      { name: "neutral", className: "bg-status-neutral" },
      { name: "destructive", className: "bg-destructive" },
    ],
  },
  {
    group: "Intent",
    tokens: [
      { name: "operate", className: "bg-operate" },
      { name: "observe", className: "bg-observe" },
      { name: "disclose", className: "bg-disclose" },
    ],
  },
];

const chartTones: ChartTone[] = ["operate", "observe", "gold", "high", "disclose"];

export function Styleguide() {
  const [tab, setTab] = useState("tokens");
  const [busyDemo, setBusyDemo] = useState(false);

  function demoBusy() {
    setBusyDemo(true);
    window.setTimeout(() => setBusyDemo(false), 1200);
  }

  return (
    <section aria-labelledby="styleguide-heading">
      <PageHeader
        titleId="styleguide-heading"
        title="Design system"
        eyebrow="Internal reference"
        description="Internal component, state, content, and accessibility contract."
        technicalDetails="This is the living specification: token values, accessibility tests, primitive contracts, and implementation examples render from the real implementation."
        actions={
          <Button type="button" onClick={() => setTab("components")}>
            Browse patterns
          </Button>
        }
      />

      <PageTabs
        idPrefix="styleguide"
        ariaLabel="Design system sections"
        active={tab}
        onChange={setTab}
        tabs={[
          { id: "tokens", label: "Tokens" },
          { id: "components", label: "Components" },
          { id: "charts", label: "Charts" },
          { id: "states", label: "States" },
        ]}
      />

      {tab === "tokens" && (
        <div {...tabPanelProps("styleguide", "tokens")} className="grid gap-6">
          <section aria-labelledby="sg-colors" className="grid gap-3">
            <h2 id="sg-colors" className="text-title font-semibold">
              Color tokens
            </h2>
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
              {colorTokens.map((group) => (
                <div key={group.group} className="ui-panel grid content-start gap-2 p-4">
                  <Eyebrow as="h3">{group.group}</Eyebrow>
                  {group.tokens.map((token) => (
                    <div key={token.name} className="flex items-center gap-3">
                      <span aria-hidden="true" className={`h-8 w-14 shrink-0 rounded-control ${token.className}`} />
                      <span className="font-mono text-caption">{token.name}</span>
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </section>

          <section aria-labelledby="sg-type" className="grid gap-3">
            <h2 id="sg-type" className="text-title font-semibold">
              Type ramp
            </h2>
            <div className="ui-panel grid gap-3 p-4">
              <p className="font-display text-display font-bold tracking-tight">Display / Syne — wordmark and rare brand moments</p>
              <p className="text-heading font-semibold">Heading — section titles</p>
              <p className="text-title font-semibold">Title — card and panel titles</p>
              <p className="text-body">Body / Sora — explanatory interface text at 15px; dense data remains 14px.</p>
              <p className="text-caption text-muted-foreground">Caption — metadata, table headers, eyebrows.</p>
              <p className="font-mono text-body">DM Mono — credential material, identifiers, commands.</p>
              <p className="text-body tabular-nums">Tabular numerals: 1,284 / 3,471 / 612 — digits align in columns.</p>
              <p className="text-body">
                <Eyebrow>Eyebrow primitive</Eyebrow> — the one quiet sentence-case micro-label; inline data uses <Num>Num</Num>: <Num>2026-07-24T00:00:00Z</Num>{" "}
                · <Num>1,284</Num> · <Num>90d</Num>.
              </p>
            </div>
          </section>

          <section aria-labelledby="sg-shape" className="grid gap-3">
            <h2 id="sg-shape" className="text-title font-semibold">
              Shape, elevation, and motion
            </h2>
            <div className="grid gap-4 md:grid-cols-3">
              <div className="ui-panel grid gap-2 p-4">
                <span className="text-caption text-muted-foreground">radius-control / radius-panel</span>
                <div className="flex gap-3">
                  <span className="h-10 w-16 rounded-control border border-border bg-muted" />
                  <span className="h-10 w-16 rounded-panel border border-border bg-muted" />
                  <span className="h-10 w-16 rounded-full border border-border bg-muted" />
                </div>
              </div>
              <div className="ui-panel grid gap-2 p-4">
                <span className="text-caption text-muted-foreground">elevation 1 / 2 / 3</span>
                <div className="flex gap-3">
                  <span className="h-10 w-16 rounded-panel bg-card shadow-elevation1" />
                  <span className="h-10 w-16 rounded-panel bg-card shadow-elevation2" />
                  <span className="h-10 w-16 rounded-panel bg-card shadow-elevation3" />
                </div>
              </div>
              <div className="ui-panel grid gap-2 p-4">
                <span className="text-caption text-muted-foreground">motion-fast 160ms / motion-base 220ms</span>
                <span className="text-body text-muted-foreground">Drawers slide, dialogs pop, overlays fade — all motion-safe gated.</span>
              </div>
            </div>
          </section>
        </div>
      )}

      {tab === "components" && (
        <div {...tabPanelProps("styleguide", "components")} className="grid gap-6">
          <section aria-labelledby="sg-buttons" className="grid gap-3">
            <h2 id="sg-buttons" className="text-title font-semibold">
              Buttons
            </h2>
            <div className="ui-panel flex flex-wrap items-center gap-3 p-4">
              <Button type="button">Primary</Button>
              <Button type="button" variant="secondary">
                Secondary
              </Button>
              <Button type="button" variant="outline">
                Outline
              </Button>
              <Button type="button" variant="ghost">
                Ghost
              </Button>
              <Button type="button" variant="destructive">
                Destructive
              </Button>
              <Button type="button" variant="destructive-outline">
                Destructive outline
              </Button>
              <Button type="button" loading={busyDemo} onClick={demoBusy}>
                {busyDemo ? "Working" : "Click for loading"}
              </Button>
              <Button type="button" disabled>
                Disabled
              </Button>
            </div>
          </section>

          <section aria-labelledby="sg-page-anatomy" className="grid gap-3">
            <h2 id="sg-page-anatomy" className="text-title font-semibold">
              Quiet page anatomy
            </h2>
            <div className="grid gap-4 border-y border-border py-4 md:grid-cols-[minmax(0,1.5fr)_auto]">
              <div>
                <Eyebrow as="p">Answer</Eyebrow>
                <h3 className="mt-1 text-heading font-semibold">3 credentials need attention.</h3>
                <p className="mt-1 text-body text-muted-foreground">1 critical and 2 high. Everything else is healthy.</p>
                <ul className="mt-4 divide-y divide-border text-body">
                  <li className="flex justify-between gap-4 py-2">
                    <span>api.example.test</span>
                    <span className="text-risk-critical">Critical</span>
                  </li>
                  <li className="flex justify-between gap-4 py-2">
                    <span>payments/database</span>
                    <span className="text-risk-high">High</span>
                  </li>
                </ul>
              </div>
              <div className="min-w-44">
                <Eyebrow as="p">Do next</Eyebrow>
                <Button type="button" className="mt-1">
                  Review top issue
                </Button>
                <details className="mt-4 text-caption text-muted-foreground">
                  <summary className="cursor-pointer font-medium">Technical details</summary>
                  <p className="mt-1">Risk inputs, evidence IDs, projection version, event history, and recovery controls.</p>
                </details>
              </div>
            </div>
          </section>

          <section aria-labelledby="sg-badges" className="grid gap-3">
            <h2 id="sg-badges" className="text-title font-semibold">
              Status vocabulary
            </h2>
            <div className="ui-panel flex flex-wrap items-center gap-3 p-4">
              <StatusBadge vocabulary="certificate" value="active" />
              <StatusBadge vocabulary="certificate" value="revoked" />
              <StatusBadge vocabulary="expiry" value="critical" />
              <StatusBadge vocabulary="risk" value="high" />
              <StatusBadge vocabulary="agent" value="online" />
              <StatusBadge vocabulary="honesty" value="disclose" />
            </div>
          </section>

          <section aria-labelledby="sg-chip" className="grid gap-3">
            <h2 id="sg-chip" className="text-title font-semibold">
              Credential material
            </h2>
            <div className="ui-panel grid gap-3 p-4">
              <div className="flex flex-wrap items-center gap-3">
                <CredentialChip value="9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" label="fingerprint" head={12} tail={8} />
                <CredentialChip value="cert:8f21a4c0-77aa-4a1e-9d3e-1f2b3c0001" label="node ID" />
              </div>
              <p className="text-caption text-muted-foreground">
                DM Mono, middle-truncated (both ends of a fingerprint matter), full value on hover, one-click copy with a screen-reader announcement.
              </p>
            </div>
          </section>

          <section aria-labelledby="sg-cards" className="grid gap-3">
            <h2 id="sg-cards" className="text-title font-semibold">
              Card
            </h2>
            <div className="grid gap-4 md:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle>Evidence queue</CardTitle>
                </CardHeader>
                <CardContent>A bounded decision or object with no default shadow.</CardContent>
              </Card>
              <div className="grid gap-2">
                <Skeleton className="h-4 w-40" />
                <Skeleton className="h-8 w-full" />
                <Skeleton className="h-8 w-full" />
                <Skeleton className="h-8 w-3/4" />
              </div>
            </div>
          </section>
        </div>
      )}

      {tab === "charts" && (
        <div {...tabPanelProps("styleguide", "charts")} className="grid gap-6">
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <StatTile label="Certificates" value="1,284" hint="+12% this quarter" tone="brand" />
            <StatTile label="Expiring ≤7d" value={9} tone="critical" hint="needs action" />
            <StatTile label="Open incidents" value={2} tone="warning" />
            <StatTile label="Future-ready" value={34} tone="success" hint="+PQC" />
          </div>
          <div className="grid gap-4 lg:grid-cols-2">
            <div className="ui-panel grid gap-3 p-4">
              <h3 className="text-title font-semibold">AreaTrend</h3>
              <AreaTrend points={[42, 51, 38, 61, 73, 58, 66, 80, 72, 91, 84, 97]} ariaLabel="Sample issuance trend" />
            </div>
            <div className="ui-panel grid gap-3 p-4">
              <h3 className="text-title font-semibold">Donut with legend</h3>
              <Donut
                ariaLabel="Sample algorithm mix"
                centerLabel="1,284"
                centerSub="certificates"
                withLegend
                segments={[
                  { label: "ECDSA P-256", value: 742, tone: "operate" },
                  { label: "RSA-2048", value: 368, tone: "observe" },
                  { label: "RSA-4096", value: 131, tone: "gold" },
                  { label: "Ed25519", value: 33, tone: "high" },
                  { label: "ML-DSA-65", value: 10, tone: "disclose" },
                ]}
              />
            </div>
            <div className="ui-panel grid gap-3 p-4">
              <h3 className="text-title font-semibold">BucketBar and Meter</h3>
              <BucketBar
                ariaLabel="Sample expiry buckets"
                data={[
                  { label: "<7d", value: 9, tone: "critical" },
                  { label: "7–30d", value: 54, tone: "warning" },
                  { label: "30–90d", value: 188, tone: "info" },
                  { label: ">90d", value: 1033, tone: "success" },
                ]}
              />
              <Meter
                ariaLabel="Sample rotation coverage"
                segments={[
                  { label: "automated", value: 72, tone: "success" },
                  { label: "manual", value: 21, tone: "warning" },
                  { label: "none", value: 7, tone: "critical" },
                ]}
              />
            </div>
            <div className="ui-panel grid gap-3 p-4">
              <h3 className="text-title font-semibold">Sparkline and tone palette</h3>
              <Sparkline points={[10, 13, 16, 15, 21, 24, 26, 25, 30, 31, 33, 34]} ariaLabel="Sample sparkline" />
              <div className="flex flex-wrap gap-2">
                {chartTones.map((tone) => (
                  <span key={tone} className="inline-flex items-center gap-1.5 font-mono text-caption">
                    <span aria-hidden="true" className="h-3 w-3 rounded-sm" style={{ background: chartToneColor(tone) }} />
                    {tone}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {tab === "states" && (
        <div {...tabPanelProps("styleguide", "states")} className="grid gap-4">
          <LoadingState>Loading rows…</LoadingState>
          <ErrorState title="Could not load rows">The service returned a problem document.</ErrorState>
          <PermissionDeniedState>Your session cannot read these rows.</PermissionDeniedState>
          <UnavailableState title="Rows unavailable">This surface is fail-closed until the feature is enabled.</UnavailableState>
          <EmptyState title="Nothing here yet">Empty states pair a short explanation with the next action.</EmptyState>
        </div>
      )}
    </section>
  );
}
