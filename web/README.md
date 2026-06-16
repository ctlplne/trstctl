# trstctl web UI

The trstctl web console (F12): React 18 + Vite + TypeScript + Tailwind, with
shadcn-style components, an OIDC login flow, and read-only inventory dashboards.

## Develop

```sh
npm install
npm run dev        # Vite dev server on :5173, proxying /api and /auth to :8080
```

## Test and build

```sh
npm run typecheck  # tsc --noEmit
npm test           # Vitest (component + axe accessibility tests)
npm run build      # tsc + Vite build -> ../internal/webui/dist (embedded by the Go binary)
```

`npm run build` emits into `internal/webui/dist`, which the control-plane binary
embeds with `//go:embed` and serves from `internal/webui` (SPA fallback). From the
repository root, `make web` runs the install + build.

## Layout

- `src/components/AppShell.tsx` — authenticated layout: skip link, banner, primary
  navigation, main landmark; WCAG 2.1 AA baseline, keyboard navigable.
- `src/components/ThemeProvider.tsx` / `ThemeToggle.tsx` — light / dark / system
  (default = OS preference), persisted.
- `src/auth/AuthProvider.tsx` — resolves the session from `/auth/me`; `beginLogin`
  starts the OIDC flow via `/auth/login`. Routes are gated by `RequireAuth`.
- `src/lib/api.ts` — typed client over the REST surface.
- `src/pages/*` — Dashboard, Certificates, Owners, Risk.
