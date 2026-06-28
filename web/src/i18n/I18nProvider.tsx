import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  catalogs,
  defaultLocale,
  defaultTimeZone,
  interpolateMessage,
  isSupportedLocale,
  type Locale,
  type MessageKey,
  type MessageValues,
} from "@/i18n/messages";
import { browserTimeZone, formatDate, formatDateTime, formatNumber, formatPlural, normalizeTimeZone, type FormatPolicy } from "@/i18n/format";

export interface I18nContextValue extends FormatPolicy {
  dir: "ltr" | "rtl";
  formatDate: typeof formatDate;
  formatDateTime: typeof formatDateTime;
  formatMessage: (key: MessageKey, values?: MessageValues) => string;
  formatNumber: typeof formatNumber;
  formatPlural: typeof formatPlural;
  setLocale: (locale: Locale) => void;
  setTimeZone: (timeZone: string) => void;
  t: (key: MessageKey, values?: MessageValues) => string;
}

export interface IntlProviderProps {
  children: ReactNode;
  initialLocale?: Locale;
  initialTimeZone?: string;
  serverLocale?: Locale;
  serverTimeZone?: string;
}

const I18nContext = createContext<I18nContextValue | null>(null);

export function directionForLocale(locale: string): "ltr" | "rtl" {
  return /^(ar|fa|he|ur)(-|$)/i.test(locale) ? "rtl" : "ltr";
}

export function negotiateLocale(candidates: readonly string[] = []): Locale {
  for (const candidate of candidates) {
    if (isSupportedLocale(candidate)) return candidate;
    const language = candidate.split("-")[0]?.toLowerCase();
    if (language === "en") return "en-US";
    if (language === "es") return "es-ES";
    if (["ar", "fa", "he", "ur"].includes(language)) return "ar-XB";
  }
  return defaultLocale;
}

function initialLocalePreference(initialLocale?: Locale): Locale {
  if (initialLocale) return initialLocale;
  const languages = typeof navigator === "undefined" ? [] : navigator.languages.length > 0 ? navigator.languages : [navigator.language];
  return negotiateLocale(languages);
}

function initialTimeZonePreference(initialTimeZone?: string): string {
  if (initialTimeZone) return normalizeTimeZone(initialTimeZone);
  return normalizeTimeZone(browserTimeZone());
}

export function formatMessage(key: MessageKey, values?: MessageValues, locale: Locale = defaultLocale): string {
  const message = catalogs[locale]?.[key] ?? catalogs[defaultLocale][key];
  return interpolateMessage(message, values);
}

export function IntlProvider({ children, initialLocale, initialTimeZone, serverLocale, serverTimeZone }: IntlProviderProps) {
  const [locale, updateLocale] = useState<Locale>(() => initialLocalePreference(initialLocale));
  const [timeZone, updateTimeZone] = useState(() => initialTimeZonePreference(initialTimeZone));
  const dir = directionForLocale(locale);

  const setLocale = useCallback((nextLocale: Locale) => {
    updateLocale(nextLocale);
  }, []);

  const setTimeZone = useCallback((nextTimeZone: string) => {
    const normalized = normalizeTimeZone(nextTimeZone);
    updateTimeZone(normalized);
  }, []);

  const t = useCallback((key: MessageKey, values?: MessageValues) => formatMessage(key, values, locale), [locale]);

  const policy = useMemo<FormatPolicy>(() => ({ locale, timeZone }), [locale, timeZone]);

  useEffect(() => {
    if (serverLocale) updateLocale(serverLocale);
  }, [serverLocale]);

  useEffect(() => {
    if (serverTimeZone) updateTimeZone(normalizeTimeZone(serverTimeZone));
  }, [serverTimeZone]);

  useEffect(() => {
    document.documentElement.lang = locale;
    document.documentElement.dir = dir;
    document.documentElement.dataset.locale = locale;
    document.documentElement.dataset.timeZone = timeZone;
  }, [dir, locale, timeZone]);

  const value = useMemo<I18nContextValue>(
    () => ({
      locale,
      timeZone,
      dir,
      t,
      formatMessage: t,
      formatDate: (valueToFormat, nextPolicy = policy, options) => formatDate(valueToFormat, nextPolicy, options),
      formatDateTime: (valueToFormat, nextPolicy = policy, options) => formatDateTime(valueToFormat, nextPolicy, options),
      formatNumber: (valueToFormat, nextPolicy = policy, options) => formatNumber(valueToFormat, nextPolicy, options),
      formatPlural: (valueToFormat, forms, nextPolicy = policy) => formatPlural(valueToFormat, forms, nextPolicy),
      setLocale,
      setTimeZone,
    }),
    [dir, locale, policy, setLocale, setTimeZone, t, timeZone],
  );

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export const I18nProvider = IntlProvider;

export function useTranslation(): I18nContextValue {
  const context = useContext(I18nContext);
  if (context) return context;
  const policy: FormatPolicy = { locale: defaultLocale, timeZone: defaultTimeZone };
  const fallback = (key: MessageKey, values?: MessageValues) => formatMessage(key, values);
  return {
    ...policy,
    dir: "ltr",
    t: fallback,
    formatMessage: fallback,
    formatDate: (value, nextPolicy = policy, options) => formatDate(value, nextPolicy, options),
    formatDateTime: (value, nextPolicy = policy, options) => formatDateTime(value, nextPolicy, options),
    formatNumber: (value, nextPolicy = policy, options) => formatNumber(value, nextPolicy, options),
    formatPlural: (value, forms, nextPolicy = policy) => formatPlural(value, forms, nextPolicy),
    setLocale: () => {},
    setTimeZone: () => {},
  };
}
