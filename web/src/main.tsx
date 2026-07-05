import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
// Self-hosted brand fonts (no runtime network call): Sora for body text,
// DM Mono for machine identifiers, Syne for display/brand — matching the
// trstctl.com design language.
import "@fontsource-variable/sora";
import "@fontsource-variable/syne";
import "@fontsource/dm-mono/400.css";
import "@fontsource/dm-mono/500.css";
import { App } from "@/App";
import "@/index.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
