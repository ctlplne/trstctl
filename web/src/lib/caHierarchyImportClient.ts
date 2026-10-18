import { mutate, req } from "./apiTransport";
import type { CAExistingImportCSR, CAPrepareExistingImportCSRRequest } from "./api-types.gen";

// Loaded only when an operator prepares or recovers an external-CA CSR.
export function prepareExistingImportCSR(input: CAPrepareExistingImportCSRRequest): Promise<CAExistingImportCSR> {
  return mutate<CAExistingImportCSR>("POST", "/api/v1/ca/authorities/imported/csr", input);
}

export function getExistingImportCSR(ceremonyID: string): Promise<CAExistingImportCSR> {
  return req<CAExistingImportCSR>(`/api/v1/ca/authorities/imported/csr/${encodeURIComponent(ceremonyID)}`);
}
