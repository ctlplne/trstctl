import { z } from "zod";
import type { ManagedTenantProvisionRequest } from "@/lib/api-types.gen";

export type ManagedTenantPrincipal = { tenantId: string; subject: string };
export type ManagedTenantAttempt = {
  version: 1;
  scope: string;
  principal: string;
  key: string;
  createdAt: string;
  request: ManagedTenantProvisionRequest;
};

export type ManagedTenantRecoveryCode =
  | "invalid_request"
  | "storage_unavailable"
  | "pending_request_changed"
  | "pending_limit"
  | "invalid_record"
  | "unverified_response";
export class ManagedTenantRecoveryError extends Error {
  constructor(readonly code: ManagedTenantRecoveryCode) {
    super(code);
  }
}

const databaseName = "trstctl-managed-tenant-recovery";
const storeName = "attempts";
const maxPending = 128;
const utf8 = new TextEncoder();
const bounded = (max: number) =>
  z
    .string()
    .trim()
    .refine((value) => utf8.encode(value).length <= max);
const optionalMetadata = bounded(80).optional();
export const managedTenantRequestSchema = z
  .object({
    tenant_id: z
      .string()
      .trim()
      .uuid()
      .transform((value) => value.toLowerCase()),
    name: bounded(120).refine((value) => value.length > 0),
    region: optionalMetadata,
    data_residency: optionalMetadata,
    plan: optionalMetadata,
    support_tier: optionalMetadata,
    slo_tier: optionalMetadata,
  })
  .strict();

function principalKey(principal: ManagedTenantPrincipal): string {
  if (!principal.tenantId || !principal.subject) throw new ManagedTenantRecoveryError("invalid_request");
  return JSON.stringify([principal.tenantId, principal.subject]);
}

function normalizeRequest(value: unknown): ManagedTenantProvisionRequest {
  const parsed = managedTenantRequestSchema.safeParse(value);
  if (!parsed.success) throw new ManagedTenantRecoveryError("invalid_request");
  const request: ManagedTenantProvisionRequest = { tenant_id: parsed.data.tenant_id, name: parsed.data.name };
  for (const field of ["region", "data_residency", "plan", "support_tier", "slo_tier"] as const) {
    if (parsed.data[field]) request[field] = parsed.data[field];
  }
  return request;
}

function validateRecord(value: unknown, principal: string): ManagedTenantAttempt {
  if (!value || typeof value !== "object") throw new ManagedTenantRecoveryError("invalid_record");
  const record = value as Partial<ManagedTenantAttempt>;
  let request: ManagedTenantProvisionRequest;
  try {
    request = normalizeRequest(record.request);
  } catch {
    throw new ManagedTenantRecoveryError("invalid_record");
  }
  // Restoration must never silently change a previously attempted body. Records
  // written here are canonical; unexpected edits require explicit recovery.
  const raw = record.request;
  if (
    !raw ||
    Object.keys(raw).length !== Object.keys(request).length ||
    Object.entries(request).some(([field, value]) => raw[field as keyof ManagedTenantProvisionRequest] !== value)
  ) {
    throw new ManagedTenantRecoveryError("invalid_record");
  }
  const scope = JSON.stringify([principal, request.tenant_id]);
  if (
    record.version !== 1 ||
    record.principal !== principal ||
    record.scope !== scope ||
    typeof record.key !== "string" ||
    !z.string().uuid().safeParse(record.key).success ||
    typeof record.createdAt !== "string" ||
    !Number.isFinite(Date.parse(record.createdAt))
  ) {
    throw new ManagedTenantRecoveryError("invalid_record");
  }
  return { version: 1, scope, principal, key: record.key, createdAt: record.createdAt, request };
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") return reject(new ManagedTenantRecoveryError("storage_unavailable"));
    let opening: IDBOpenDBRequest;
    try {
      opening = indexedDB.open(databaseName, 1);
    } catch {
      reject(new ManagedTenantRecoveryError("storage_unavailable"));
      return;
    }
    opening.onupgradeneeded = () => {
      const store = opening.result.createObjectStore(storeName, { keyPath: "scope" });
      store.createIndex("principal", "principal", { unique: false });
    };
    let refused = false;
    const refuse = () => {
      refused = true;
      reject(new ManagedTenantRecoveryError("storage_unavailable"));
    };
    opening.onerror = refuse;
    opening.onblocked = refuse;
    opening.onsuccess = () => {
      if (refused) {
        opening.result.close();
        return;
      }
      opening.result.onversionchange = () => opening.result.close();
      resolve(opening.result);
    };
  });
}

// IndexedDB commits the intent before any network mutation. Its read/write
// transaction serializes competing tabs; a same-request contender receives the
// first tab's key. No session, CSRF token, credential or license is stored here.
export async function prepareManagedTenantAttempt(principal: ManagedTenantPrincipal, input: ManagedTenantProvisionRequest): Promise<ManagedTenantAttempt> {
  const owner = principalKey(principal);
  const request = normalizeRequest(input);
  const scope = JSON.stringify([owner, request.tenant_id]);
  const db = await openDatabase();
  try {
    return await new Promise<ManagedTenantAttempt>((resolve, reject) => {
      const tx = db.transaction(storeName, "readwrite");
      const store = tx.objectStore(storeName);
      let result: ManagedTenantAttempt | undefined;
      let failure: unknown;
      const abort = (error: unknown) => {
        failure = error;
        tx.abort();
      };
      tx.onabort = () => reject(failure ?? new ManagedTenantRecoveryError("storage_unavailable"));
      tx.onerror = () => {
        failure ??= new ManagedTenantRecoveryError("storage_unavailable");
      };
      tx.oncomplete = () => (result ? resolve(result) : reject(new ManagedTenantRecoveryError("storage_unavailable")));
      const existing = store.get(scope);
      existing.onsuccess = () => {
        try {
          if (existing.result !== undefined) {
            result = validateRecord(existing.result, owner);
            if (JSON.stringify(result.request) !== JSON.stringify(request)) throw new ManagedTenantRecoveryError("pending_request_changed");
            return;
          }
          const count = store.index("principal").count(owner);
          count.onsuccess = () => {
            try {
              if (count.result >= maxPending) throw new ManagedTenantRecoveryError("pending_limit");
              result = { version: 1, scope, principal: owner, key: crypto.randomUUID(), createdAt: new Date().toISOString(), request };
              store.add(result);
            } catch (error) {
              abort(error);
            }
          };
        } catch (error) {
          abort(error);
        }
      };
    });
  } finally {
    db.close();
  }
}

export async function listManagedTenantAttempts(principal: ManagedTenantPrincipal): Promise<ManagedTenantAttempt[]> {
  const owner = principalKey(principal);
  const db = await openDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(storeName, "readonly");
      let records: ManagedTenantAttempt[] | undefined;
      let failure: unknown;
      tx.onabort = () => reject(failure ?? new ManagedTenantRecoveryError("storage_unavailable"));
      tx.onerror = () => {
        failure ??= new ManagedTenantRecoveryError("storage_unavailable");
      };
      tx.oncomplete = () => (records ? resolve(records) : reject(new ManagedTenantRecoveryError("storage_unavailable")));
      const read = tx.objectStore(storeName).index("principal").getAll(owner);
      read.onsuccess = () => {
        try {
          records = read.result.map((record: unknown) => validateRecord(record, owner));
        } catch (error) {
          failure = error;
          tx.abort();
        }
      };
    });
  } finally {
    db.close();
  }
}

// A successful network response is checked by the caller before forgetting the
// intent. Compare the original key inside the transaction so a late response
// cannot delete a later attempt. Failure to delete leaves a safe replay record.
export async function completeManagedTenantAttempt(principal: ManagedTenantPrincipal, attempt: ManagedTenantAttempt): Promise<void> {
  const owner = principalKey(principal);
  const expected = validateRecord(attempt, owner);
  const db = await openDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(storeName, "readwrite");
      const store = tx.objectStore(storeName);
      tx.oncomplete = () => resolve();
      tx.onabort = () => reject(new ManagedTenantRecoveryError("storage_unavailable"));
      const read = store.get(expected.scope);
      read.onsuccess = () => {
        try {
          if (read.result === undefined) return;
          const current = validateRecord(read.result, owner);
          if (current.key === expected.key) store.delete(expected.scope);
        } catch {
          tx.abort();
        }
      };
    });
  } finally {
    db.close();
  }
}
