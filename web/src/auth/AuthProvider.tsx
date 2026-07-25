import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { api, loginURL, setPreviewTransportIsolation, UnauthorizedError, type Me } from "@/lib/api";

/** The static demo build (demo.trstctl.com) sets VITE_TRSTCTL_DEMO=1 at
 * build time: preview becomes available in a production bundle AND starts
 * automatically, so the visitor lands signed-in on the showcase with the
 * transport isolated. The product embed never sets the flag — the
 * embed-purity gate (internal/webui) proves the shipped dist carries no
 * preview identity. */
const demoBuild = import.meta.env.VITE_TRSTCTL_DEMO === "1";
const previewAllowed = import.meta.env.DEV || demoBuild;

interface AuthState {
  user: Me | null;
  loading: boolean;
  error: string | null;
  preview: boolean;
  previewAvailable: boolean;
  startPreview: () => void;
  logout: () => Promise<void>;
}

type AuthCoreState = Omit<AuthState, "startPreview" | "logout">;

const previewUser: Me = {
  subject: "dev-preview",
  tenant_id: "dev-tenant",
  email: "preview@trstctl.local",
  roles: ["admin"],
  permissions: ["*"],
};

const AuthContext = createContext<AuthState>({
  user: null,
  loading: true,
  error: null,
  preview: false,
  previewAvailable: false,
  startPreview: () => {},
  logout: async () => {},
});

/** AuthProvider resolves the current session from /auth/me on mount. */
export function AuthProvider({ children }: { children: ReactNode }) {
  const previewRef = useRef(demoBuild);
  if (demoBuild) setPreviewTransportIsolation(true);
  const [state, setState] = useState<AuthCoreState>(
    demoBuild
      ? // Demo build: land signed-in on the showcase — no /auth/me round-trip,
        // no login click, transport already isolated above.
        { user: previewUser, loading: false, error: null, preview: true, previewAvailable: true }
      : { user: null, loading: true, error: null, preview: false, previewAvailable: previewAllowed },
  );

  const startPreview = useCallback(() => {
    if (!previewAllowed) return;
    previewRef.current = true;
    setPreviewTransportIsolation(true);
    setState({
      user: previewUser,
      loading: false,
      error: null,
      preview: true,
      previewAvailable: true,
    });
  }, []);

  const logout = useCallback(async () => {
    if (previewRef.current) {
      previewRef.current = false;
      setPreviewTransportIsolation(false);
      setState({ user: null, loading: false, error: null, preview: false, previewAvailable: previewAllowed });
      return;
    }

    setState((current) => ({ ...current, error: null }));
    try {
      await api.logout();
      setState({ user: null, loading: false, error: null, preview: false, previewAvailable: previewAllowed });
    } catch (err) {
      setState((current) => ({ ...current, loading: false, error: String(err) }));
      throw err;
    }
  }, []);

  useEffect(() => {
    if (demoBuild) return; // no session to resolve — preview is the session
    let active = true;
    api
      .me()
      .then((user) => {
        if (!active || previewRef.current) return;
        setState({ user, loading: false, error: null, preview: false, previewAvailable: import.meta.env.DEV });
      })
      .catch((err) => {
        if (!active || previewRef.current) return;
        if (err instanceof UnauthorizedError) {
          setState({ user: null, loading: false, error: null, preview: false, previewAvailable: import.meta.env.DEV });
        } else {
          setState({ user: null, loading: false, error: String(err), preview: false, previewAvailable: import.meta.env.DEV });
        }
      });
    return () => {
      active = false;
    };
  }, []);

  return <AuthContext.Provider value={{ ...state, startPreview, logout }}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  return useContext(AuthContext);
}

/** beginLogin sends the browser into the OIDC flow. */
export function beginLogin() {
  window.location.assign(loginURL);
}
