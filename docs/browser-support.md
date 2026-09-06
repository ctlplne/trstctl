# Browser support

The console is a single-page application served by the control plane with a strict
content security policy. Support is declared by evidence, not by intent:

| Engine | Browsers | Evidence |
| --- | --- | --- |
| Chromium | Chrome, Edge, Brave (current and previous major) | Playwright live-browser matrix in CI (`npx playwright install --with-deps chromium firefox webkit`) |
| Gecko | Firefox (current and ESR) | CI matrix; the cold design-partner evaluation of 2026-09-06 drove every journey in Firefox from an isolated profile with TLS validation on |
| WebKit | Safari (current) | CI matrix |

What "supported" means here: the primary journeys (setup, discovery, ownership,
connectors and endpoint lifecycle, identities, certificates, alert routing, audit
export) render and operate with keyboard and pointer, at 200% zoom and in a
375-pixel-wide viewport, with no horizontal scrolling of the page body.

Not supported: Internet Explorer, browsers with JavaScript disabled, and browsers
that cannot present the trust you chose for the control plane's certificate (see
[Local evaluation TLS](local-evaluation-tls.md)).
