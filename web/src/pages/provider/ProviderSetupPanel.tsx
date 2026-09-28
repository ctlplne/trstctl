// SPDX-License-Identifier: BUSL-1.1

import { useEffect, useRef } from "react";
import { CredentialChip } from "@/components/CredentialChip";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { translateNow } from "@/i18n/I18nProvider";
import { ProviderAuthError, providerApi, type ProviderTenant } from "@/lib/providerApi";
import { useApiQuery } from "@/lib/query";

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

export function ProviderSetupPanel({
  tenant,
  authorityKey,
  onAuthError,
  onClose,
}: {
  tenant: ProviderTenant;
  authorityKey: readonly unknown[];
  onAuthError: () => void;
  onClose: () => void;
}) {
  const panel = useRef<HTMLElement>(null);
  useEffect(() => {
    panel.current?.focus();
  }, [tenant.id]);
  const health = useApiQuery(["provider", "setup", ...authorityKey, tenant.id], () => providerApi.customerHealth(tenant.id), { retry: false });
  useEffect(() => {
    if (health.errorValue instanceof ProviderAuthError) onAuthError();
  }, [health.errorValue, onAuthError]);
  // A failed refresh invalidates the setup verdict even if the query cache has
  // an older successful response. Missing fields on older servers stay unknown.
  const snapshot = !health.error && !health.fetching ? health.data : null;
  const configured = snapshot?.workspace_initialized;
  const active = tenant.status === "active";
  const command = `(umask 077; set -C; trstctl token create --tenant ${shellQuote(tenant.id)} --tenant-name ${shellQuote(tenant.name)} --subject customer-bootstrap-admin > ${shellQuote(`./customer-${tenant.id}.token`)})`;
  return (
    <section ref={panel} tabIndex={-1} className="mt-4" aria-labelledby="provider-setup-title">
      <Card>
        <CardHeader>
          <CardTitle id="provider-setup-title">{translateNow("provider.setup.title", { customer: tenant.name })}</CardTitle>
          <p className="text-caption text-muted-foreground">{translateNow("provider.setup.serviceHelp")}</p>
        </CardHeader>
        <CardContent className="space-y-3">
          {health.loading || health.fetching ? (
            <Skeleton className="h-20 w-full" />
          ) : (
            <div role="status">
              <p className="font-semibold">
                {translateNow(configured === true ? "provider.setup.configured" : configured === false ? "provider.setup.required" : "provider.setup.unknown")}
              </p>
              {configured === undefined ? <p className="mt-1 text-caption text-muted-foreground">{translateNow("provider.setup.unknownHelp")}</p> : null}
            </div>
          )}
          {!active ? (
            <p className="text-caption">{translateNow("provider.setup.inactive")}</p>
          ) : configured === false ? (
            <>
              <p className="text-caption">{translateNow("provider.setup.adminHelp")}</p>
              <details open>
                <summary className="cursor-pointer text-caption font-medium">{translateNow("provider.setup.command")}</summary>
                <div className="mt-2">
                  <CredentialChip value={command} label={translateNow("provider.setup.commandLabel")} fullValue />
                </div>
                <p className="mt-2 text-caption text-muted-foreground">{translateNow("provider.setup.fileHelp")}</p>
              </details>
              <p className="text-caption">{translateNow("provider.setup.metering")}</p>
            </>
          ) : configured === true ? (
            <>
              <p className="text-caption">{translateNow("provider.setup.next")}</p>
              <p className="text-caption text-muted-foreground">{translateNow("provider.setup.coverage")}</p>
            </>
          ) : null}
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" loading={health.fetching} onClick={health.refetch}>
              {translateNow("provider.setup.refresh")}
            </Button>
            <Button type="button" variant="outline" onClick={onClose}>
              {translateNow("provider.setup.close")}
            </Button>
          </div>
        </CardContent>
      </Card>
    </section>
  );
}
