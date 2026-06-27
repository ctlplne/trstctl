import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
// Self-hosted brand fonts (no runtime network call): Inter for body text,
// JetBrains Mono for machine identifiers — matching the certctl identity.
import "@fontsource-variable/inter";
import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/500.css";
import "@fontsource/jetbrains-mono/600.css";
import { App } from "@/App";
import "@/index.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
