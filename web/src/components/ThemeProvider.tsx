import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

export type Theme = "light" | "dark" | "system";

interface ThemeContextValue {
  theme: Theme;
  setTheme: (t: Theme) => void;
  resolved: "light" | "dark";
}

const ThemeContext = createContext<ThemeContextValue | null>(null);
const STORAGE_KEY = "certctl-theme";

function systemPrefersDark(): boolean {
  return typeof window !== "undefined" && window.matchMedia("(prefers-color-scheme: dark)").matches;
}

/** ThemeProvider drives light/dark/system theming, defaulting to the OS setting
 * and persisting the choice. */
export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(() => {
    const stored = typeof localStorage !== "undefined" ? (localStorage.getItem(STORAGE_KEY) as Theme | null) : null;
    return stored ?? "system";
  });

  const resolved: "light" | "dark" = theme === "system" ? (systemPrefersDark() ? "dark" : "light") : theme;

  useEffect(() => {
    document.documentElement.classList.toggle("dark", resolved === "dark");
  }, [resolved]);

  const setTheme = (t: Theme) => {
    try {
      localStorage.setItem(STORAGE_KEY, t);
    } catch {
      /* storage may be unavailable; theme still applies for the session */
    }
    setThemeState(t);
  };

  return <ThemeContext.Provider value={{ theme, setTheme, resolved }}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used within ThemeProvider");
  return ctx;
}
