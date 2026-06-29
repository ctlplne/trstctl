import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { api, loginURL, UnauthorizedError, type Me } from "@/lib/api";

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
  const previewRef = useRef(false);
  const [state, setState] = useState<AuthCoreState>({
    user: null,
    loading: true,
    error: null,
    preview: false,
    previewAvailable: import.meta.env.DEV,
  });

  const startPreview = useCallback(() => {
    if (!import.meta.env.DEV) return;
    previewRef.current = true;
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
      setState({ user: null, loading: false, error: null, preview: false, previewAvailable: import.meta.env.DEV });
      return;
    }

    setState((current) => ({ ...current, error: null }));
    try {
      await api.logout();
      setState({ user: null, loading: false, error: null, preview: false, previewAvailable: import.meta.env.DEV });
    } catch (err) {
      setState((current) => ({ ...current, loading: false, error: String(err) }));
      throw err;
    }
  }, []);

  useEffect(() => {
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
