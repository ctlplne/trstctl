import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api, loginURL, UnauthorizedError, type Me } from "@/lib/api";

interface AuthState {
  user: Me | null;
  loading: boolean;
  error: string | null;
}

const AuthContext = createContext<AuthState>({ user: null, loading: true, error: null });

/** AuthProvider resolves the current session from /auth/me on mount. */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ user: null, loading: true, error: null });

  useEffect(() => {
    let active = true;
    api
      .me()
      .then((user) => active && setState({ user, loading: false, error: null }))
      .catch((err) => {
        if (!active) return;
        if (err instanceof UnauthorizedError) {
          setState({ user: null, loading: false, error: null });
        } else {
          setState({ user: null, loading: false, error: String(err) });
        }
      });
    return () => {
      active = false;
    };
  }, []);

  return <AuthContext.Provider value={state}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  return useContext(AuthContext);
}

/** beginLogin sends the browser into the OIDC flow. */
export function beginLogin() {
  window.location.assign(loginURL);
}
