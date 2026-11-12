import { mutate, req } from "./apiTransport";

// A245-L4: an operations ledger action runs the exact request the server named
// for it: its route's review first, when the route has one, then the request
// itself. Only ever a POST to this API's own routes; the path comes from the
// server, and nothing else is sent.

/** operationActionPath admits only this API's own routes. */
function operationActionPath(path: string): string {
  if (!/^\/api\/v1\/[A-Za-z0-9._~\-/]+$/.test(path) || path.includes("..")) {
    throw new Error("An operation action names a route outside this API.");
  }
  return path;
}

/** previewOperationAction sends the action's request to its route's review,
 * a read-only POST, so it carries no Idempotency-Key. */
export async function previewOperationAction(path: string, body: unknown): Promise<unknown> {
  return req<unknown>(operationActionPath(path), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

/** runOperationAction sends the action's request, with an Idempotency-Key. */
export async function runOperationAction(method: string, path: string, body: unknown): Promise<unknown> {
  if (method !== "POST") throw new Error("An operation action is a POST to this API.");
  return mutate<unknown>("POST", operationActionPath(path), body);
}
