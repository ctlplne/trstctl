import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  defaultLocale,
  defaultTimeZone,
  eagerCatalogs,
  interpolateMessage,
  isLazyLocale,
  isSupportedLocale,
  lazyCatalogLoaders,
  type LazyLocale,
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
    if (language === "de") return "de-DE";
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

/* S-C10: es/de catalogs are lazy modules. The cache below is module-scope so
 * a catalog loads once per session; until it resolves, lookups fall back to
 * English — never to raw keys. loadLocaleCatalog de-duplicates in-flight
 * loads and reports whether anything new arrived (the provider bumps a
 * version to re-render translated copy on arrival). */
const loadedCatalogs: Partial<Record<LazyLocale, Record<MessageKey, string>>> = {};
const catalogLoads: Partial<Record<LazyLocale, Promise<boolean>>> = {};

export function loadLocaleCatalog(locale: Locale): Promise<boolean> {
  if (!isLazyLocale(locale)) return Promise.resolve(false);
  if (loadedCatalogs[locale]) return Promise.resolve(false);
  const inFlight = catalogLoads[locale];
  if (inFlight) return inFlight;
  const load = lazyCatalogLoaders[locale]()
    .then((module) => {
      loadedCatalogs[locale] = module.default;
      return true;
    })
    .catch(() => {
      // Fail open to English; a retry happens on the next locale switch.
      delete catalogLoads[locale];
      return false;
    });
  catalogLoads[locale] = load;
  return load;
}

function catalogFor(locale: Locale): Record<MessageKey, string> | undefined {
  return isLazyLocale(locale) ? loadedCatalogs[locale] : eagerCatalogs[locale];
}

export function formatMessage(key: MessageKey, values?: MessageValues, locale: Locale = defaultLocale): string {
  const message = catalogFor(locale)?.[key] ?? eagerCatalogs[defaultLocale][key];
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

  // S-C10: lazy locales resolve their catalog on demand; the version bump
  // re-renders the tree so English fallback copy swaps to the translation the
  // moment the module arrives. Loading is idempotent and cached module-wide.
  const [catalogVersion, setCatalogVersion] = useState(0);
  useEffect(() => {
    let cancelled = false;
    void loadLocaleCatalog(locale).then((changed) => {
      if (changed && !cancelled) setCatalogVersion((current) => current + 1);
    });
    return () => {
      cancelled = true;
    };
  }, [locale]);

  const setLocale = useCallback((nextLocale: Locale) => {
    updateLocale(nextLocale);
  }, []);

  const setTimeZone = useCallback((nextTimeZone: string) => {
    const normalized = normalizeTimeZone(nextTimeZone);
    updateTimeZone(normalized);
  }, []);

  // catalogVersion is a real dependency: the same (key, locale) pair resolves
  // differently once the lazy catalog lands.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const t = useCallback((key: MessageKey, values?: MessageValues) => formatMessage(key, values, locale), [locale, catalogVersion]);

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
