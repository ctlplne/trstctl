// Typed client over the certctl REST surface (S3.3 / S7.1). All requests carry
// the session cookie; a 401 surfaces as UnauthorizedError so the auth layer can
// redirect to login.

export class UnauthorizedError extends Error {
  constructor() {
    super("unauthorized");
    this.name = "UnauthorizedError";
  }
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, body: string) {
    super(`request failed (${status})`);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
  body: string;
}

export interface Me {
  subject: string;
  tenant_id: string;
  email?: string;
}

export interface Certificate {
  id: string;
  subject: string;
  issuer?: string;
  not_after?: string;
  status?: string;
}

export interface Owner {
  id: string;
  kind: string;
  name: string;
  email?: string;
}

export interface CredentialRisk {
  credential_id: string;
  subject: string;
  kind: string;
  score: number;
  exposure: number;
  owner_active: boolean;
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    credentials: "include",
    headers: { Accept: "application/json" },
    ...init,
  });
  if (res.status === 401) throw new UnauthorizedError();
  if (!res.ok) throw new ApiError(res.status, await res.text());
  return (await res.json()) as T;
}

/** Api is the client surface the UI depends on; it is mockable in tests. */
export interface Api {
  me(): Promise<Me>;
  certificates(): Promise<Certificate[]>;
  owners(): Promise<Owner[]>;
  risk(): Promise<CredentialRisk[]>;
}

export const api: Api = {
  me: () => req<Me>("/auth/me"),
  certificates: () =>
    req<{ certificates: Certificate[] }>("/api/v1/certificates").then((r) => r.certificates ?? []),
  owners: () => req<{ owners: Owner[] }>("/api/v1/owners").then((r) => r.owners ?? []),
  risk: () =>
    req<{ credentials: CredentialRisk[] }>("/api/v1/risk/credentials?sort=score").then(
      (r) => r.credentials ?? [],
    ),
};

/** loginURL is where the browser is sent to begin the OIDC flow. */
export const loginURL = "/auth/login";
