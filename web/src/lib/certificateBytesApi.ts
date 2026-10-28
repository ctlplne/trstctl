import { mutate } from "./apiTransport";
import type { CertificateDERRecovery, CertificateDERRecoveryRequest } from "./api-types.gen";

// Certificate byte recovery: give an inventory row that holds only what was
// recorded about a certificate the certificate itself, from the tenant's CA
// records or the endpoint the row names.

/** Recover a row's certificate bytes by the chosen method. */
export const recoverCertificateDER = (certificateId: string, input: CertificateDERRecoveryRequest, idempotencyKey?: string) =>
  mutate<CertificateDERRecovery>("POST", `/api/v1/certificates/${encodeURIComponent(certificateId)}/der-recovery`, input, idempotencyKey);
