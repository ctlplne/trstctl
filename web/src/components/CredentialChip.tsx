import { useEffect, useRef, useState } from "react";
import { Check, Copy } from "lucide-react";
import { useTranslation } from "@/i18n/I18nProvider";
import { cn } from "@/lib/utils";

/** middleTruncate keeps the head and tail of an identifier visible — for
 * fingerprints, serials, and opaque IDs the two ends are what operators
 * actually compare, so end-ellipsis truncation is the wrong tool. */
export function middleTruncate(value: string, head = 10, tail = 6): string {
  const trimmed = value.trim();
  if (trimmed.length <= head + tail + 1) return trimmed;
  return `${trimmed.slice(0, head)}…${trimmed.slice(-tail)}`;
}

/** CredentialChip is the standard rendering for cryptographic material and
 * machine identifiers (fingerprints, serials, node IDs, enrollment tokens):
 * DM Mono, middle-truncated with the full value on hover, and a one-click
 * copy affordance with a polite screen-reader announcement. Do not nest it
 * inside another interactive element (it contains a button). */
export function CredentialChip({
  value,
  label = "identifier",
  head,
  tail,
  fullValue = false,
  className,
}: {
  value: string;
  /** Human name for the copy button's accessible label, e.g. "serial number". */
  label?: string;
  head?: number;
  tail?: number;
  /** Only inside deliberate exact-evidence disclosure: wrap the whole value. */
  fullValue?: boolean;
  className?: string;
}) {
  const { t } = useTranslation();
  const [copied, setCopied] = useState(false);
  const [copyFailed, setCopyFailed] = useState(false);
  const timer = useRef<number>();

  useEffect(() => () => window.clearTimeout(timer.current), []);
  useEffect(() => {
    window.clearTimeout(timer.current);
    setCopied(false);
    setCopyFailed(false);
  }, [value]);

  async function copyValue() {
    try {
      await navigator.clipboard.writeText(value);
      setCopyFailed(false);
      setCopied(true);
      window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
      setCopyFailed(true);
    }
  }

  return (
    <span
      data-credential-chip
      className={cn(
        "inline-flex max-w-full items-center gap-1 rounded-control border border-border bg-muted/60 px-1.5 py-0.5 font-mono text-caption text-foreground",
        (fullValue || copyFailed) && "items-start",
        className,
      )}
    >
      <span title={value} className={fullValue || copyFailed ? "min-w-0 whitespace-normal break-all" : "truncate"}>
        {fullValue || copyFailed ? value : middleTruncate(value, head, tail)}
      </span>
      <button
        type="button"
        aria-label={t("credentialChip.copy", { label })}
        onClick={() => void copyValue()}
        className="shrink-0 rounded-sm p-0.5 text-muted-foreground transition-colors duration-fast hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus"
      >
        {copied ? <Check className="h-3 w-3 text-status-success" aria-hidden="true" /> : <Copy className="h-3 w-3" aria-hidden="true" />}
      </button>
      <span role="status" className={copyFailed ? "font-sans text-caption" : "sr-only"}>
        {copyFailed ? t("credentialChip.copyFailed") : copied ? t("credentialChip.copied") : ""}
      </span>
    </span>
  );
}
