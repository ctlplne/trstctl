import type { Meta, StoryObj } from "@storybook/react-vite";
import {
  AreaTrend,
  BucketBar,
  chartToneColor,
  Donut,
  Meter,
  Sparkline,
  StackedTimeBarChart,
  StatTile,
  TimeBarChart,
  type ChartTone,
} from "@/components/charts";

/** Every chart pulls from the semantic tone palette (DESIGN.md rule 9) —
 * never hand-picked hues. Several tokens alias in dark mode; flip the theme
 * toolbar to check a multi-series composition in both themes. */
const meta = {
  title: "Components/Charts",
  component: StatTile,
} satisfies Meta<typeof StatTile>;

export default meta;
type Story = StoryObj<typeof meta>;

const tones: ChartTone[] = ["critical", "high", "medium", "low", "neutral", "success", "warning", "info", "brand", "operate", "observe", "disclose", "gold"];

export const TonePalette: Story = {
  args: { label: "", value: "" },
  render: () => (
    <div className="flex max-w-2xl flex-wrap gap-3">
      {tones.map((tone) => (
        <span key={tone} className="flex items-center gap-1.5 text-caption text-muted-foreground">
          <span aria-hidden="true" className="h-3.5 w-3.5 rounded-sm" style={{ background: chartToneColor(tone) }} />
          {tone}
        </span>
      ))}
    </div>
  ),
};

export const StatTiles: Story = {
  args: { label: "Certificates", value: 1284 },
  render: () => (
    <div className="grid max-w-3xl grid-cols-2 gap-4 md:grid-cols-4">
      <StatTile label="Certificates" value={1284} hint="+12 today" tone="brand" />
      <StatTile label="Expiring in 30d" value={37} hint="9 within 7d" tone="warning" />
      <StatTile label="Open incidents" value={2} tone="critical" />
      <StatTile label="Rotation success" value="99.4%" hint="last 30 days" tone="success" />
    </div>
  ),
};

export const MeterStory: Story = {
  args: { label: "", value: "" },
  name: "Meter",
  render: () => (
    <div className="max-w-md">
      <Meter
        ariaLabel="Risk distribution"
        segments={[
          { value: 3, tone: "critical", label: "critical" },
          { value: 11, tone: "high", label: "high" },
          { value: 42, tone: "medium", label: "medium" },
          { value: 108, tone: "low", label: "low" },
        ]}
      />
    </div>
  ),
};

export const BucketBarStory: Story = {
  args: { label: "", value: "" },
  name: "BucketBar",
  render: () => (
    <BucketBar
      ariaLabel="Certificates by expiry bucket"
      data={[
        { label: "<7d", value: 9, tone: "critical" },
        { label: "7–30d", value: 28, tone: "warning" },
        { label: "30–90d", value: 122, tone: "info" },
        { label: ">90d", value: 1125, tone: "success" },
      ]}
    />
  ),
};

export const TimeBars: Story = {
  args: { label: "", value: "" },
  render: () => (
    <TimeBarChart
      ariaLabel="Issuance per day"
      tone="brand"
      data={[
        { label: "Mon", value: 34 },
        { label: "Tue", value: 41 },
        { label: "Wed", value: 28 },
        { label: "Thu", value: 52 },
        { label: "Fri", value: 47 },
        { label: "Sat", value: 12 },
        { label: "Sun", value: 9 },
      ]}
    />
  ),
};

// The same localized ranges used by the lifecycle cockpit, at a narrow panel
// width. Keep this fixture for visual review of tick spacing and full units.
export const RenewalWindows: Story = {
  args: { label: "", value: "" },
  render: () => (
    <div className="grid max-w-xs gap-4">
      {["days", "días", "Tage"].map((unit) => (
        <TimeBarChart
          key={unit}
          ariaLabel={`Renewal windows (${unit})`}
          tone="warning"
          data={Array.from({ length: 6 }, (_, index) => ({ label: `${index * 15}–${index * 15 + 14} ${unit}`, value: [0, 2, 8, 5, 13, 1][index]! }))}
        />
      ))}
    </div>
  ),
};

export const StackedTimeBars: Story = {
  args: { label: "", value: "" },
  render: () => (
    <StackedTimeBarChart
      ariaLabel="Rotations by outcome per week"
      data={["W27", "W28", "W29", "W30"].map((label, index) => ({
        label,
        segments: [
          { label: "succeeded", value: [42, 51, 38, 47][index], tone: "success" },
          { label: "retried", value: [4, 2, 6, 3][index], tone: "warning" },
          { label: "failed", value: [1, 0, 2, 1][index], tone: "critical" },
        ],
      }))}
    />
  ),
};

export const DonutStory: Story = {
  args: { label: "", value: "" },
  name: "Donut",
  render: () => (
    <Donut
      ariaLabel="NHI inventory by kind"
      centerLabel="1,731"
      centerSub="identities"
      withLegend
      segments={[
        { value: 1284, tone: "brand", label: "certificates" },
        { value: 214, tone: "operate", label: "workloads" },
        { value: 158, tone: "info", label: "service accounts" },
        { value: 75, tone: "gold", label: "AI agents" },
      ]}
    />
  ),
};

export const Trends: Story = {
  args: { label: "", value: "" },
  render: () => (
    <div className="max-w-2xl space-y-6">
      <div className="flex items-center gap-3">
        <span className="text-body text-muted-foreground">p95 issuance latency</span>
        <Sparkline points={[220, 208, 231, 190, 184, 197, 176]} ariaLabel="p95 issuance latency, last 7 days" tone="observe" />
      </div>
      <AreaTrend ariaLabel="Managed identities, last 12 weeks" tone="brand" points={[1180, 1204, 1231, 1266, 1289, 1315, 1362, 1398, 1441, 1502, 1594, 1731]} />
    </div>
  ),
};
