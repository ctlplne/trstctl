import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { api, loginURL, UnauthorizedError, type Me } from "@/lib/api";

interface AuthState {
  user: Me | null;
  loading: boolean;
  error: string | null;
  preview: boolean;
  previewAvailable: boolean;
  startPreview: () => void;
}

const previewUser: Me = {
  subject: "dev-preview",
  tenant_id: "dev-tenant",
  email: "preview@trstctl.local",
};

const AuthContext = createContext<AuthState>({
  user: null,
  loading: true,
  error: null,
  preview: false,
  previewAvailable: false,
  startPreview: () => {},
});

/** AuthProvider resolves the current session from /auth/me on mount. */
export function AuthProvider({ children }: { children: ReactNode }) {
  const previewRef = useRef(false);
  const [state, setState] = useState<AuthState>({
    user: null,
    loading: true,
    error: null,
    preview: false,
    previewAvailable: import.meta.env.DEV,
    startPreview: () => {},
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
      startPreview,
    });
  }, []);

  useEffect(() => {
    let active = true;
    api
      .me()
      .then((user) => {
        if (!active || previewRef.current) return;
        setState({ user, loading: false, error: null, preview: false, previewAvailable: import.meta.env.DEV, startPreview });
      })
      .catch((err) => {
        if (!active || previewRef.current) return;
        if (err instanceof UnauthorizedError) {
          setState({ user: null, loading: false, error: null, preview: false, previewAvailable: import.meta.env.DEV, startPreview });
        } else {
          setState({ user: null, loading: false, error: String(err), preview: false, previewAvailable: import.meta.env.DEV, startPreview });
        }
      });
    return () => {
      active = false;
    };
  }, [startPreview]);

  return <AuthContext.Provider value={state}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  return useContext(AuthContext);
}

/** beginLogin sends the browser into the OIDC flow. */
export function beginLogin() {
  window.location.assign(loginURL);
}
