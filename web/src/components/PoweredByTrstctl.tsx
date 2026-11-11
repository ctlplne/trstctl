import { useLayoutEffect, useRef, type CSSProperties } from "react";
import { useTranslation } from "@/i18n/I18nProvider";

// MSP-1: every surface that shows a Provider customer's brand also shows
// "Powered by trstctl", and nothing the brand carries can hide it. The mark
// uses no design token, so no token override reaches it: fixed trstctl colors
// on its own opaque chip (white on deep forest, over 14:1, whatever the page
// background or theme), a fixed 12px font and a 22px minimum height. The
// properties that could hide it are also set !important on the element, so no
// stylesheet rule outranks them.

const markStyle: CSSProperties = {
  display: "inline-flex",
  alignItems: "center",
  gap: "6px",
  flexShrink: 0,
  minHeight: "22px",
  padding: "3px 10px",
  borderRadius: "9999px",
  background: "#0b2e24",
  color: "#ffffff",
  boxShadow: "0 0 0 1px #ffffff",
  font: "600 12px/16px system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif",
  letterSpacing: "0",
  textTransform: "none",
  textDecoration: "none",
  whiteSpace: "nowrap",
  position: "relative",
  zIndex: 1,
};

const enforced: Record<string, string> = {
  display: "inline-flex",
  visibility: "visible",
  opacity: "1",
  color: "#ffffff",
  "background-color": "#0b2e24",
  "font-size": "12px",
  "line-height": "16px",
  "min-height": "22px",
  filter: "none",
  transform: "none",
  "clip-path": "none",
};

export function PoweredByTrstctl({ className }: { className?: string }) {
  const { t } = useTranslation();
  const ref = useRef<HTMLAnchorElement>(null);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    for (const [property, value] of Object.entries(enforced)) el.style.setProperty(property, value, "important");
  }, []);
  return (
    <a ref={ref} href="https://trstctl.com" target="_blank" rel="noopener noreferrer" data-testid="powered-by-trstctl" className={className} style={markStyle}>
      <svg aria-hidden="true" viewBox="0 0 32 32" width="14" height="14" fill="none" style={{ flexShrink: 0 }}>
        <circle cx="16" cy="16" r="10" stroke="#ffffff" strokeWidth="2.6" />
        <path d="M6.60 12.6H25.40M16 12.6V22.8" stroke="#ffffff" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      {t("brand.poweredBy")}
    </a>
  );
}
