import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  defaultLocale,
  defaultTimeZone,
  eagerCatalogs,
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
    if (candidate.split("-")[0]?.toLowerCase() === "en") return defaultLocale;
  }
  return defaultLocale;
}

function supportedPreference(locale?: Locale): Locale {
  if (locale && isSupportedLocale(locale) && (locale === defaultLocale || import.meta.env.DEV)) return locale;
  return defaultLocale;
}

function initialLocalePreference(initialLocale?: Locale): Locale {
  if (initialLocale) return supportedPreference(initialLocale);
  const languages = typeof navigator === "undefined" ? [] : navigator.languages.length > 0 ? navigator.languages : [navigator.language];
  return negotiateLocale(languages);
}

function initialTimeZonePreference(initialTimeZone?: string): string {
  if (initialTimeZone) return normalizeTimeZone(initialTimeZone);
  return normalizeTimeZone(browserTimeZone());
}

export function formatMessage(key: MessageKey, values?: MessageValues, locale: Locale = defaultLocale): string {
  const message = eagerCatalogs[locale]?.[key] ?? eagerCatalogs[defaultLocale][key];
  return interpolateMessage(message, values);
}

/* activeLocale mirrors the provider's current locale for module-scope copy.
 * The DA-14 sweep keys strings in plain helpers and config factories where the
 * useTranslation hook cannot reach; translateNow reads this mirror instead.
 * Locale changes re-render the whole tree under the provider, so helpers
 * re-run and pick up the new locale on the same pass. Outside a provider
 * (unit tests, isolated renders) it stays on the default locale. */
const activeLocaleRef: { current: Locale } = { current: defaultLocale };

/** translateNow resolves a message key against the provider's current locale
 * without requiring hook scope (C-I1, DA-14 sweep). */
export function translateNow(key: MessageKey, values?: MessageValues): string {
  return formatMessage(key, values, activeLocaleRef.current);
}

export function IntlProvider({ children, initialLocale, initialTimeZone, serverLocale, serverTimeZone }: IntlProviderProps) {
  const [locale, updateLocale] = useState<Locale>(() => initialLocalePreference(initialLocale));
  // Mirror for translateNow (set during render so module-scope copy resolved
  // in this same pass already sees the new locale — the mutation is idempotent
  // per pass). The unmount cleanup resets the mirror so renders outside any
  // provider (unit tests, isolated mounts) fall back to the default locale
  // instead of inheriting a stale one.
  // The mirror write is idempotent per pass and must happen during render:
  // module-scope copy (translateNow) resolved later in this same pass needs
  // the new locale, and an effect-only write would leave the first painted
  // pass stale.
  // eslint-disable-next-line react-hooks/immutability
  activeLocaleRef.current = locale;
  useEffect(() => {
    activeLocaleRef.current = locale;
    return () => {
      activeLocaleRef.current = defaultLocale;
    };
  }, [locale]);
  const [timeZone, updateTimeZone] = useState(() => initialTimeZonePreference(initialTimeZone));
  const dir = directionForLocale(locale);

  const setLocale = useCallback((nextLocale: Locale) => {
    updateLocale(supportedPreference(nextLocale));
  }, []);

  const setTimeZone = useCallback((nextTimeZone: string) => {
    const normalized = normalizeTimeZone(nextTimeZone);
    updateTimeZone(normalized);
  }, []);

  const t = useCallback((key: MessageKey, values?: MessageValues) => formatMessage(key, values, locale), [locale]);

  const policy = useMemo<FormatPolicy>(() => ({ locale, timeZone }), [locale, timeZone]);

  useEffect(() => {
    if (serverLocale) updateLocale(supportedPreference(serverLocale));
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
