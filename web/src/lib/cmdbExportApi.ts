import { mutate, req } from "@/lib/apiTransport";
import type { CMDBCertificateExport, CMDBCertificateExportBindingList, CMDBCertificateExportInput } from "@/lib/api-types.gen";

const root = "/api/v1/integrations/cmdb";
export const cmdbExportApi = {
  bindings: (signal?: AbortSignal) => req<CMDBCertificateExportBindingList>(`${root}/certificate-export-bindings`, { signal }),
  queue: (input: CMDBCertificateExportInput, key: string) => mutate<CMDBCertificateExport>("POST", `${root}/certificate-exports`, input, key),
  status: (id: string, signal?: AbortSignal) => req<CMDBCertificateExport>(`${root}/certificate-exports/${encodeURIComponent(id)}`, { signal }),
};
