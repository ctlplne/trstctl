// SPDX-License-Identifier: MPL-2.0

import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { translateNow } from "@/i18n/I18nProvider";
import { formatDateTime } from "@/i18n/format";
import { ProviderAuthError, providerApi, type ProviderOperation, type ProviderOperatorAccess, type ProviderOperatorRole } from "@/lib/providerApi";
import { useApiQuery, useQueryClient } from "@/lib/query";

const operations = ["read", "provision", "suspend", "offboard", "break_glass"] as const satisfies readonly ProviderOperation[];

const grantSchema = z.object({
  operatorId: z.string().trim().min(1, translateNow("source.provider.access.operator.aud580003")),
  customerId: z.string().trim().min(1, translateNow("source.provider.access.customer.aud580004")),
  operation: z.enum(operations),
  expiresAt: z.string().trim(),
});
type GrantForm = z.infer<typeof grantSchema>;

export function ProviderAccessPanel({ onAuthError }: { onAuthError: () => void }) {
  const access = useApiQuery(["provider", "operator-access"], providerApi.listOperatorAccess);
  const customers = useApiQuery(["provider", "access-customers"], providerApi.listAccessCustomers);
  const queryClient = useQueryClient();
  const form = useForm<GrantForm>({
    resolver: zodResolver(grantSchema),
    defaultValues: { operatorId: "", customerId: "", operation: "read", expiresAt: "" },
  });
  const setRows = (next: ProviderOperatorAccess) => {
    queryClient.setQueryData<ProviderOperatorAccess[]>(["provider", "operator-access"], (rows) =>
      (rows ?? []).map((row) => (row.identity.id === next.identity.id ? next : row)),
    );
    void queryClient.invalidateQueries({ queryKey: ["provider", "operator-access"] });
  };
  const fail = (error: unknown) => {
    if (error instanceof ProviderAuthError) {
      onAuthError();
      return;
    }
    form.setError("root", { message: error instanceof Error ? error.message : String(error) });
  };
  const grant = form.handleSubmit(async (values) => {
    form.clearErrors("root");
    try {
      setRows(
        await providerApi.grantOperatorAccess(values.operatorId, {
          customer_id: values.customerId,
          operations: [values.operation],
          expires_at: values.expiresAt ? new Date(values.expiresAt).toISOString() : undefined,
        }),
      );
    } catch (error) {
      fail(error);
    }
  });
  const revoke = async (row: ProviderOperatorAccess, customerId: string, operation: ProviderOperation) => {
    try {
      setRows(
        await providerApi.revokeOperatorAccess(row.identity.id, {
          customer_id: customerId,
          operations: [operation],
          reason: "Revoked in Provider access console",
        }),
      );
    } catch (error) {
      fail(error);
    }
  };
  const setRole = async (row: ProviderOperatorAccess, role: ProviderOperatorRole) => {
    try {
      setRows(await providerApi.setOperatorRole(row.identity.id, role));
    } catch (error) {
      fail(error);
    }
  };

  return (
    <section className="mt-6" aria-labelledby="provider-access-heading">
      <h2 id="provider-access-heading" className="text-title font-semibold">
        {translateNow("source.provider.access.title.aud580001")}
      </h2>
      <p className="mt-1 text-caption text-muted-foreground">{translateNow("source.provider.access.intro.aud580002")}</p>

      <form className="mt-3 flex flex-wrap items-end gap-2" onSubmit={(event) => void grant(event)}>
        <label className="grid gap-1">
          <span className="text-caption font-medium">{translateNow("source.provider.access.operator.aud580003")}</span>
          <Select aria-label={translateNow("source.provider.access.operator.aud580003")} {...form.register("operatorId")}>
            <option value="">—</option>
            {(access.data ?? [])
              .filter((row) => row.identity.active)
              .map((row) => (
                <option key={row.identity.id} value={row.identity.id}>
                  {row.identity.display_name || row.identity.user_name} — {row.identity.user_name}
                </option>
              ))}
          </Select>
        </label>
        <label className="grid gap-1">
          <span className="text-caption font-medium">{translateNow("source.provider.access.customer.aud580004")}</span>
          <Select aria-label={translateNow("source.provider.access.customer.aud580004")} {...form.register("customerId")}>
            <option value="">—</option>
            {(customers.data ?? []).map((tenant) => (
              <option key={tenant.id} value={tenant.id}>
                {tenant.name} — {tenant.slug}
              </option>
            ))}
          </Select>
        </label>
        <label className="grid gap-1">
          <span className="text-caption font-medium">{translateNow("source.provider.access.operation.aud580005")}</span>
          <Select aria-label={translateNow("source.provider.access.operation.aud580005")} {...form.register("operation")}>
            {operations.map((operation) => (
              <option key={operation} value={operation}>
                {operation}
              </option>
            ))}
          </Select>
        </label>
        <label className="grid gap-1">
          <span className="text-caption font-medium">{translateNow("source.provider.access.expiry.aud580006")}</span>
          <Input type="datetime-local" aria-label={translateNow("source.provider.access.expiry.aud580006")} {...form.register("expiresAt")} />
        </label>
        <Button type="submit" disabled={form.formState.isSubmitting || access.loading}>
          {translateNow("source.provider.access.grant.aud580007")}
        </Button>
      </form>
      {form.formState.errors.root?.message ? <p className="mt-2 text-caption text-status-danger">{form.formState.errors.root.message}</p> : null}

      {access.loading ? (
        <p className="mt-3 text-caption text-muted-foreground">{translateNow("source.loading.4f9d1e0e3a")}</p>
      ) : access.error ? (
        <p className="mt-3 text-caption text-status-danger">{access.error}</p>
      ) : (access.data ?? []).length === 0 ? (
        <p className="mt-3 text-caption text-muted-foreground">{translateNow("source.provider.access.empty.aud580008")}</p>
      ) : (
        <div className="mt-3 overflow-x-auto">
          <table className="w-full text-caption">
            <thead>
              <tr className="text-left text-muted-foreground">
                <th className="pr-3 font-medium">{translateNow("source.provider.access.identity.aud580009")}</th>
                <th className="pr-3 font-medium">{translateNow("source.provider.access.role.aud580010")}</th>
                <th className="pr-3 font-medium">{translateNow("source.provider.access.source.aud580011")}</th>
                <th className="pr-3 font-medium">{translateNow("source.provider.access.scope.aud580012")}</th>
              </tr>
            </thead>
            <tbody>
              {(access.data ?? []).map((row) => (
                <tr key={row.identity.id} className="border-t border-border/60 align-top">
                  <td className="py-3 pr-3">
                    <span className="font-medium">{row.identity.display_name || row.identity.user_name}</span>
                    <span className="block text-muted-foreground">{row.identity.email}</span>
                    <span className={row.identity.active ? "text-status-success" : "text-status-danger"}>
                      {row.identity.active
                        ? translateNow("source.provider.access.active.aud580013")
                        : translateNow("source.provider.access.inactive.aud580014")}
                    </span>
                  </td>
                  <td className="py-3 pr-3">
                    <Select
                      aria-label={translateNow("source.provider.access.role.aud580010")}
                      value={row.identity.role}
                      disabled={!row.identity.active}
                      onChange={(event) => void setRole(row, event.target.value as ProviderOperatorRole)}
                    >
                      <option value="admin">{translateNow("source.provider.access.role.admin.aud580021")}</option>
                      <option value="operator">{translateNow("source.provider.access.role.operator.aud580022")}</option>
                    </Select>
                  </td>
                  <td className="py-3 pr-3 font-mono">{row.identity.source}</td>
                  <td className="py-3 pr-3">
                    {row.delegations.length === 0 ? (
                      <span className="text-muted-foreground">{translateNow("source.provider.access.none.aud580015")}</span>
                    ) : (
                      <ul className="space-y-2">
                        {row.delegations.map((delegation) => {
                          const active = !delegation.revoked_at && (!delegation.expires_at || Date.parse(delegation.expires_at) > Date.now());
                          return (
                            <li key={`${delegation.customer_id}:${delegation.operation}`} className="rounded-control border border-border/60 p-2">
                              <span className="font-mono">{delegation.customer_id}</span>
                              <span className="ml-2 font-medium">{delegation.operation}</span>
                              <span className="ml-2 text-muted-foreground">{delegation.source}</span>
                              {delegation.expires_at ? (
                                <span className="block text-muted-foreground">
                                  {translateNow("source.provider.access.expires.aud580016")}: {formatDateTime(delegation.expires_at)}
                                </span>
                              ) : null}
                              {delegation.last_used_at ? (
                                <span className="block text-muted-foreground">
                                  {translateNow("source.provider.access.lastused.aud580017")}: {formatDateTime(delegation.last_used_at)}
                                </span>
                              ) : null}
                              {delegation.revoked_at ? (
                                <span className="block text-status-danger">
                                  {translateNow("source.provider.access.revoked.aud580018")}: {formatDateTime(delegation.revoked_at)}
                                </span>
                              ) : active ? (
                                <Button
                                  type="button"
                                  size="sm"
                                  variant="outline"
                                  className="mt-1"
                                  onClick={() => void revoke(row, delegation.customer_id, delegation.operation)}
                                >
                                  {translateNow("source.provider.access.revoke.aud580019")}
                                </Button>
                              ) : null}
                            </li>
                          );
                        })}
                      </ul>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
