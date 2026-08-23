import { defaultLocale, defaultTimeZone, type Locale } from "@/i18n/messages";

export interface FormatPolicy {
  locale: Locale;
  timeZone: string;
}

export function browserTimeZone(): string {
  return Intl.DateTimeFormat().resolvedOptions().timeZone || defaultTimeZone;
}

export function normalizeTimeZone(value?: string | null): string {
  if (!value) return defaultTimeZone;
  try {
    new Intl.DateTimeFormat(defaultLocale, { timeZone: value }).format(new Date(0));
    return value;
  } catch {
    return defaultTimeZone;
  }
}

export function formatDateTime(
  value: Date | number | string | undefined,
  policy: FormatPolicy = { locale: defaultLocale, timeZone: defaultTimeZone },
  options: Intl.DateTimeFormatOptions = {},
): string {
  if (value == null || value === "") return "-";
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  // Go's zero time is serialized as year 0001. It means "not recorded", not a
  // real operator date, so never render it as the confidence-breaking Jan 1, 1.
  if (date.getUTCFullYear() <= 1) return "-";
  return new Intl.DateTimeFormat(policy.locale, {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: normalizeTimeZone(policy.timeZone),
    ...options,
  }).format(date);
}

export function formatDate(
  value: Date | number | string | undefined,
  policy: FormatPolicy = { locale: defaultLocale, timeZone: defaultTimeZone },
  options: Intl.DateTimeFormatOptions = {},
): string {
  return formatDateTime(value, policy, { dateStyle: "medium", timeStyle: undefined, ...options });
}

export function formatShortDate(
  value: Date | number | string | undefined,
  policy: FormatPolicy = { locale: defaultLocale, timeZone: defaultTimeZone },
  options: Intl.DateTimeFormatOptions = {},
): string {
  if (value == null || value === "") return "-";
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  if (date.getUTCFullYear() <= 1) return "-";
  return new Intl.DateTimeFormat(policy.locale, {
    month: "short",
    day: "numeric",
    timeZone: normalizeTimeZone(policy.timeZone),
    ...options,
  }).format(date);
}

export function formatNumber(
  value: number,
  policy: FormatPolicy = { locale: defaultLocale, timeZone: defaultTimeZone },
  options: Intl.NumberFormatOptions = {},
): string {
  return new Intl.NumberFormat(policy.locale, options).format(value);
}

export function formatCurrency(
  value: number,
  policy: FormatPolicy = { locale: defaultLocale, timeZone: defaultTimeZone },
  options: Intl.NumberFormatOptions = {},
): string {
  return formatNumber(value, policy, { style: "currency", currency: "USD", ...options });
}

export function formatPlural(
  value: number,
  forms: Partial<Record<Intl.LDMLPluralRule, string>> & { other: string },
  policy: FormatPolicy = { locale: defaultLocale, timeZone: defaultTimeZone },
): string {
  const rule = new Intl.PluralRules(policy.locale).select(value);
  return forms[rule] ?? forms.other;
}
