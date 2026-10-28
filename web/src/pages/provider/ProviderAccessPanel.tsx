// SPDX-License-Identifier: BUSL-1.1

import { useEffect, useState } from "react";
import { DataGrid } from "@/components/DataGrid";
import { DetailDrawer } from "@/components/DetailDrawer";
import { CredentialChip } from "@/components/CredentialChip";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { translateNow } from "@/i18n/I18nProvider";
import { formatDateTime } from "@/i18n/format";
import {
  ProviderAuthError,
  providerApi,
  type ProviderOperation,
  type ProviderOperatorAccess,
  type ProviderOperatorRole,
  type ProviderRole,
  type ProviderRoleCatalog,
} from "@/lib/providerApi";
import { useApiQuery, useQueryClient } from "@/lib/query";

const operations = ["read", "provision", "suspend", "resume", "offboard", "break-glass"] as const satisfies readonly ProviderOperation[];

function grantSourceLabel(source: string): string {
  if (source === "provider_api") return translateNow("provider.access.delegations.source.http");
  if (source === "console") return translateNow("provider.access.delegations.source.legacy");
  return source;
}

const grantSchema = z.object({
  operatorId: z.string().trim().min(1, translateNow("source.provider.access.operator.aud580003")),
  customerId: z.string().trim().min(1, translateNow("source.provider.access.customer.aud580004")),
  operation: z.enum(operations),
  expiresAt: z.string().trim(),
});
type GrantForm = z.infer<typeof grantSchema>;

const builtInRoleCatalog: ProviderRoleCatalog = {
  roles: [
    { name: "admin", permissions: [], built_in: true },
    { name: "operator", permissions: [], built_in: true },
  ],
  permissions: [],
};

export function ProviderAccessPanel({ onAuthError, canWrite, rolesWrite = false }: { onAuthError: () => void; canWrite: boolean; rolesWrite?: boolean }) {
  const access = useApiQuery(["provider", "operator-access"], providerApi.listOperatorAccess, { live: { intervalMs: 15_000 } });
  // A90: the role catalog drives the role select and the custom-role editor.
  // An older or mocked client without the roles read keeps the built-ins.
  const roleCatalog = useApiQuery(["provider", "roles"], async () =>
    typeof providerApi.listRoles === "function" ? ((await providerApi.listRoles()) ?? builtInRoleCatalog) : builtInRoleCatalog,
  );
  const catalog = roleCatalog.data ?? builtInRoleCatalog;
  const [roleName, setRoleName] = useState("");
  const [roleDescription, setRoleDescription] = useState("");
  const [rolePermissions, setRolePermissions] = useState<string[]>([]);
  const [roleStatus, setRoleStatus] = useState("");
  const [roleError, setRoleError] = useState("");
  const customers = useApiQuery(["provider", "access-customers"], providerApi.listAccessCustomers, { live: { intervalMs: 15_000 } });
  const queryClient = useQueryClient();
  const [selectedOperatorId, setSelectedOperatorId] = useState<string | null>(null);
  const [firstGrantId, setFirstGrantId] = useState<string | null>(null);
  // Resolve details from current served rows. Never retain a copied grant across
  // refreshes or after its operator disappears from the current authority view.
  const selectedOperator = access.error ? undefined : access.data?.find((row) => row.identity.id === selectedOperatorId);
  useEffect(() => {
    if (selectedOperatorId && (access.error || (access.data && !access.data.some((row) => row.identity.id === selectedOperatorId)))) {
      setSelectedOperatorId(null);
      setFirstGrantId(null);
    }
  }, [access.data, access.error, selectedOperatorId]);
  const grants = selectedOperator?.delegations ?? [];
  const grantId = (grant: ProviderOperatorAccess["delegations"][number]) =>
    `${grant.customer_id}:${grant.operation}:${grant.grant_event_id ?? grant.granted_at}`;
  const grantStart =
    grants.length > 10 && firstGrantId
      ? Math.max(
          0,
          grants.findIndex((grant) => grantId(grant) === firstGrantId),
        )
      : 0;
  const grantPage = grants.slice(grantStart, grantStart + 10);
  useEffect(() => {
    if (
      selectedOperator &&
      firstGrantId &&
      (selectedOperator.delegations.length <= 10 || !selectedOperator.delegations.some((grant) => grantId(grant) === firstGrantId))
    ) {
      setFirstGrantId(null);
    }
  }, [selectedOperator, firstGrantId]);
  const form = useForm<GrantForm>({
    resolver: zodResolver(grantSchema),
    defaultValues: { operatorId: "", customerId: "", operation: "read", expiresAt: "" },
  });
  const setRows = (next: ProviderOperatorAccess) => {
    queryClient.setQueryData<ProviderOperatorAccess[]>(["provider", "operator-access"], (rows) =>
      (rows ?? []).map((row) => (row.identity.id === next.identity.id ? next : row)),
    );
    void queryClient.invalidateQueries({ queryKey: ["provider", "operator-access"] });
    void queryClient.invalidateQueries({ queryKey: ["provider", "session"] });
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
  const refreshRoles = () => {
    void queryClient.invalidateQueries({ queryKey: ["provider", "roles"] });
    void queryClient.invalidateQueries({ queryKey: ["provider", "session"] });
  };
  const saveRole = async () => {
    setRoleError("");
    setRoleStatus("");
    try {
      const saved = await providerApi.putRole(roleName.trim(), { description: roleDescription.trim(), permissions: rolePermissions });
      setRoleStatus(translateNow("provider.access.roles.saved", { name: saved.name }));
      setRoleName("");
      setRoleDescription("");
      setRolePermissions([]);
      refreshRoles();
    } catch (error) {
      if (error instanceof ProviderAuthError) {
        onAuthError();
        return;
      }
      setRoleError(error instanceof Error ? error.message : String(error));
    }
  };
  const deleteRole = async (role: ProviderRole) => {
    setRoleError("");
    setRoleStatus("");
    try {
      await providerApi.deleteRole(role.name);
      setRoleStatus(translateNow("provider.access.roles.deleted", { name: role.name }));
      refreshRoles();
    } catch (error) {
      if (error instanceof ProviderAuthError) {
        onAuthError();
        return;
      }
      setRoleError(error instanceof Error ? error.message : String(error));
    }
  };
  const editRole = (role: ProviderRole) => {
    setRoleName(role.name);
    setRoleDescription(role.description ?? "");
    setRolePermissions([...role.permissions]);
    setRoleStatus("");
    setRoleError("");
  };
  const customRoles = catalog.roles.filter((role) => !role.built_in);

  return (
    <section className="mt-6" aria-labelledby="provider-access-heading">
      <h2 id="provider-access-heading" className="text-title font-semibold">
        {translateNow("source.provider.access.title.aud580001")}
      </h2>
      <p className="mt-1 text-caption text-muted-foreground">{translateNow("source.provider.access.intro.aud580002")}</p>
      <p className="mt-1 text-caption text-muted-foreground">{translateNow("provider.access.role.ceiling")}</p>

      {canWrite ? (
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
      ) : null}
      {form.formState.errors.root?.message ? <p className="mt-2 text-caption text-status-danger">{form.formState.errors.root.message}</p> : null}

      <DataGrid
        ariaLabel={translateNow("source.provider.access.title.aud580001")}
        className="mt-3"
        rows={access.data ?? []}
        getRowId={(row) => row.identity.id}
        state={access.error ? "error" : access.loading ? "loading" : access.data?.length ? "ready" : "empty"}
        stateMessage={access.error || translateNow("source.provider.access.empty.aud580008")}
        columns={[
          {
            id: "identity",
            header: translateNow("source.provider.access.identity.aud580009"),
            cell: (row) => (
              <div className="grid gap-1">
                <span className="font-medium">{row.identity.display_name || row.identity.user_name}</span>
                <span className="text-muted-foreground">{row.identity.email}</span>
                <span className={row.identity.active ? "text-status-success" : "text-status-danger"}>
                  {translateNow(row.identity.active ? "source.provider.access.active.aud580013" : "source.provider.access.inactive.aud580014")}
                </span>
              </div>
            ),
          },
          {
            id: "role",
            header: translateNow("source.provider.access.role.aud580010"),
            cell: (row) =>
              canWrite ? (
                <Select
                  aria-label={translateNow("source.provider.access.role.aud580010")}
                  value={row.identity.role}
                  disabled={!row.identity.active}
                  onChange={(event) => void setRole(row, event.target.value as ProviderOperatorRole)}
                >
                  {row.identity.role === "" && (
                    <option value="" disabled>
                      {translateNow("provider.access.role.unassigned")}
                    </option>
                  )}
                  <option value="admin">{translateNow("source.provider.access.role.admin.aud580021")}</option>
                  <option value="operator">{translateNow("source.provider.access.role.operator.aud580022")}</option>
                  {customRoles.map((role) => (
                    <option key={role.name} value={role.name}>
                      {role.name}
                    </option>
                  ))}
                </Select>
              ) : (
                <span>{row.identity.role || translateNow("provider.access.role.unassigned")}</span>
              ),
          },
          {
            id: "source",
            header: translateNow("source.provider.access.source.aud580011"),
            cell: (row) => <span className="font-mono">{row.identity.source}</span>,
          },
          {
            id: "scope",
            header: translateNow("source.provider.access.scope.aud580012"),
            cell: (row) =>
              row.delegations.length === 0 ? (
                <span className="text-muted-foreground">{translateNow("source.provider.access.none.aud580015")}</span>
              ) : (
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    setFirstGrantId(null);
                    setSelectedOperatorId(row.identity.id);
                  }}
                >
                  {translateNow("provider.access.delegations.open", { count: row.delegations.length })}
                </Button>
              ),
          },
        ]}
      />
      <DetailDrawer
        open={!!selectedOperator}
        className="max-w-5xl"
        title={translateNow("provider.access.delegations.title", {
          operator: selectedOperator?.identity.display_name || selectedOperator?.identity.user_name || "",
        })}
        description={translateNow("provider.access.delegations.description")}
        onClose={() => setSelectedOperatorId(null)}
      >
        <DataGrid
          ariaLabel={translateNow("source.provider.access.scope.aud580012")}
          rows={grantPage}
          getRowId={grantId}
          stateMessage={translateNow("source.provider.access.none.aud580015")}
          pagination={
            grants.length > 10 ? (
              <div className="flex flex-wrap items-center gap-2">
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={grantStart === 0}
                  onClick={() => {
                    const row = grantStart > 10 ? grants[grantStart - 10] : undefined;
                    setFirstGrantId(row ? grantId(row) : null);
                  }}
                >
                  {translateNow("provider.access.delegations.previous")}
                </Button>
                <span className="text-caption text-muted-foreground" aria-live="polite">
                  {translateNow("provider.access.delegations.range", { start: grantStart + 1, end: grantStart + grantPage.length, total: grants.length })}
                </span>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={grantStart + grantPage.length >= grants.length}
                  onClick={() => {
                    const row = grants[grantStart + 10];
                    setFirstGrantId(row ? grantId(row) : null);
                  }}
                >
                  {translateNow("provider.access.delegations.next")}
                </Button>
              </div>
            ) : undefined
          }
          columns={[
            {
              id: "customer",
              header: translateNow("source.provider.access.customer.aud580004"),
              cell: (grant) => (
                <CredentialChip
                  value={grant.customer_id}
                  fullValue={grant.customer_id.length <= 24}
                  label={translateNow("source.provider.access.customer.aud580004")}
                />
              ),
            },
            { id: "operation", header: translateNow("source.provider.access.operation.aud580005"), cell: (grant) => grant.operation },
            { id: "source", header: translateNow("provider.access.delegations.source"), cell: (grant) => grantSourceLabel(grant.source) },
            {
              id: "evidence",
              header: translateNow("provider.access.delegations.evidence"),
              cell: (grant) => (
                <div className="grid gap-1 whitespace-nowrap text-muted-foreground">
                  <span>
                    {translateNow("provider.access.delegations.granted")}: {formatDateTime(grant.granted_at)}
                  </span>
                  {grant.expires_at ? (
                    <span>
                      {translateNow("source.provider.access.expires.aud580016")}: {formatDateTime(grant.expires_at)}
                    </span>
                  ) : null}
                  {grant.last_used_at ? (
                    <span>
                      {translateNow("source.provider.access.lastused.aud580017")}: {formatDateTime(grant.last_used_at)}
                    </span>
                  ) : null}
                  {grant.revoked_at ? (
                    <span className="text-status-danger">
                      {translateNow("source.provider.access.revoked.aud580018")}: {formatDateTime(grant.revoked_at)}
                    </span>
                  ) : null}
                </div>
              ),
            },
            {
              id: "actions",
              header: translateNow("source.provider.col.actions.l3prov0017"),
              cell: (grant) =>
                selectedOperator && canWrite && !grant.revoked_at && (!grant.expires_at || Date.parse(grant.expires_at) > Date.now()) ? (
                  <Button
                    type="button"
                    size="sm"
                    variant="destructive-outline"
                    onClick={() => void revoke(selectedOperator, grant.customer_id, grant.operation)}
                  >
                    {translateNow("source.provider.access.revoke.aud580019")}
                  </Button>
                ) : null,
            },
          ]}
        />
      </DetailDrawer>

      {rolesWrite ? (
        <section className="mt-6 rounded-control border border-border p-3" aria-labelledby="provider-roles-heading">
          <h3 id="provider-roles-heading" className="text-sm font-semibold">
            {translateNow("provider.access.roles.heading")}
          </h3>
          <p className="mt-1 text-caption text-muted-foreground">{translateNow("provider.access.roles.intro")}</p>
          {customRoles.length === 0 ? (
            <p className="mt-2 text-caption text-muted-foreground">{translateNow("provider.access.roles.none")}</p>
          ) : (
            <ul className="mt-2 grid gap-1">
              {customRoles.map((role) => (
                <li key={role.name} className="flex flex-wrap items-center gap-2 text-sm">
                  <span className="font-mono">{role.name}</span>
                  <span className="text-caption text-muted-foreground">{role.permissions.join(", ")}</span>
                  <Button type="button" size="sm" variant="outline" onClick={() => editRole(role)}>
                    {translateNow("provider.access.roles.edit")}
                  </Button>
                  <Button type="button" size="sm" variant="destructive-outline" onClick={() => void deleteRole(role)}>
                    {translateNow("provider.access.roles.delete")}
                  </Button>
                </li>
              ))}
            </ul>
          )}
          <div className="mt-3 grid gap-2 md:grid-cols-2">
            <label className="grid gap-1 text-sm">
              {translateNow("provider.access.roles.name")}
              <Input value={roleName} onChange={(event) => setRoleName(event.target.value)} />
            </label>
            <label className="grid gap-1 text-sm">
              {translateNow("provider.access.roles.description")}
              <Input value={roleDescription} onChange={(event) => setRoleDescription(event.target.value)} />
            </label>
          </div>
          <fieldset className="mt-2 grid gap-1 text-sm">
            <legend className="font-medium">{translateNow("provider.access.roles.permissions")}</legend>
            {catalog.permissions.map((permission) => (
              <label key={permission.name} className="flex flex-wrap items-start gap-2">
                <input
                  type="checkbox"
                  aria-label={permission.name}
                  className="mt-1 h-4 w-4"
                  checked={rolePermissions.includes(permission.name)}
                  onChange={(event) =>
                    setRolePermissions((current) => (event.target.checked ? [...current, permission.name] : current.filter((name) => name !== permission.name)))
                  }
                />
                <span className="font-mono">{permission.name}</span>
                <span className="block text-caption text-muted-foreground">{permission.description}</span>
              </label>
            ))}
          </fieldset>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <Button type="button" disabled={!roleName.trim() || rolePermissions.length === 0} onClick={() => void saveRole()}>
              {translateNow("provider.access.roles.save")}
            </Button>
            {roleStatus ? (
              <span role="status" className="text-caption text-success">
                {roleStatus}
              </span>
            ) : null}
            {roleError ? (
              <span role="alert" className="text-caption text-risk-critical">
                {roleError}
              </span>
            ) : null}
          </div>
        </section>
      ) : null}
    </section>
  );
}
