/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Every color carries `/ <alpha-value>` so opacity utilities work
        // (e.g. bg-brand-accent/10 for the Clarity soft-tint pills/rows).
        border: "hsl(var(--border) / <alpha-value>)",
        background: "hsl(var(--background) / <alpha-value>)",
        foreground: "hsl(var(--foreground) / <alpha-value>)",
        muted: { DEFAULT: "hsl(var(--muted) / <alpha-value>)", foreground: "hsl(var(--muted-foreground) / <alpha-value>)" },
        primary: { DEFAULT: "hsl(var(--primary) / <alpha-value>)", foreground: "hsl(var(--primary-foreground) / <alpha-value>)" },
        destructive: { DEFAULT: "hsl(var(--destructive) / <alpha-value>)", foreground: "hsl(var(--destructive-foreground) / <alpha-value>)" },
        card: { DEFAULT: "hsl(var(--card) / <alpha-value>)", foreground: "hsl(var(--card-foreground) / <alpha-value>)" },
        brand: { accent: "hsl(var(--brand-accent) / <alpha-value>)", foreground: "hsl(var(--brand-accent-foreground) / <alpha-value>)" },
        console: { accent: "hsl(var(--console-accent) / <alpha-value>)" },
        operate: { DEFAULT: "hsl(var(--operate) / <alpha-value>)", foreground: "hsl(var(--operate-foreground) / <alpha-value>)" },
        observe: { DEFAULT: "hsl(var(--observe) / <alpha-value>)", foreground: "hsl(var(--observe-foreground) / <alpha-value>)" },
        disclose: { DEFAULT: "hsl(var(--disclose) / <alpha-value>)", foreground: "hsl(var(--disclose-foreground) / <alpha-value>)" },
        risk: {
          critical: "hsl(var(--risk-critical) / <alpha-value>)",
          high: "hsl(var(--risk-high) / <alpha-value>)",
          medium: "hsl(var(--risk-medium) / <alpha-value>)",
          low: "hsl(var(--risk-low) / <alpha-value>)",
          none: "hsl(var(--risk-none) / <alpha-value>)",
        },
        status: {
          success: "hsl(var(--status-success) / <alpha-value>)",
          warning: "hsl(var(--status-warning) / <alpha-value>)",
          neutral: "hsl(var(--status-neutral) / <alpha-value>)",
          info: "hsl(var(--status-info) / <alpha-value>)",
        },
        sidebar: {
          DEFAULT: "hsl(var(--sidebar) / <alpha-value>)",
          hover: "hsl(var(--sidebar-hover) / <alpha-value>)",
          active: "hsl(var(--sidebar-active) / <alpha-value>)",
          foreground: "hsl(var(--sidebar-foreground) / <alpha-value>)",
        },
      },
      fontFamily: {
        sans: ['"Inter Variable"', "Inter", "ui-sans-serif", "-apple-system", "BlinkMacSystemFont", '"Segoe UI"', "Roboto", "Helvetica", "Arial", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "SFMono-Regular", "Menlo", "Monaco", "Consolas", "monospace"],
      },
      borderRadius: {
        control: "var(--radius-control)",
        panel: "var(--radius-panel)",
      },
      boxShadow: {
        elevation1: "var(--elevation-1)",
        elevation2: "var(--elevation-2)",
        elevation3: "var(--elevation-3)",
      },
      fontSize: {
        caption: ["var(--font-size-caption)", { lineHeight: "var(--line-height-caption)" }],
        body: ["var(--font-size-body)", { lineHeight: "var(--line-height-body)" }],
        title: ["var(--font-size-title)", { lineHeight: "var(--line-height-title)" }],
        heading: ["var(--font-size-heading)", { lineHeight: "var(--line-height-heading)" }],
        display: ["var(--font-size-display)", { lineHeight: "var(--line-height-display)" }],
      },
      spacing: {
        compact: "var(--density-compact)",
        comfortable: "var(--density-comfortable)",
      },
    },
  },
  plugins: [],
};
