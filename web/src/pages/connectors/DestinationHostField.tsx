import { useInfiniteQuery } from "@tanstack/react-query";
import { z } from "zod";
import { api } from "@/lib/api";
import { Field } from "@/components/ui/field";
import { Select } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";

const configSchema = z.record(z.string(), z.unknown());

// This field edits the same reviewed config that the API fingerprints. Changing
// the JSON or selecting an agent cannot leave a second, hidden routing value.
// agentRole "network" picks the relay that renews an appliance whose key the
// appliance generates (A122); the default picks the host a service runs on.
export function DestinationHostField({
  config,
  onChange,
  required,
  agentRole = "host",
}: {
  config: string;
  onChange: (value: string) => void;
  required: boolean;
  agentRole?: "host" | "network";
}) {
  const { t } = useTranslation();
  const fleet = useInfiniteQuery({
    queryKey: ["agents", "destination-hosts"],
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam }) => api.agentPage({ limit: 100, cursor: pageParam }),
    getNextPageParam: (page) => page.next_cursor || undefined,
  });
  let parsed: Record<string, unknown> | null = null;
  try {
    const result = configSchema.safeParse(JSON.parse(config));
    if (result.success) parsed = result.data;
  } catch {
    /* The existing configuration field retains the invalid input. */
  }
  const selected = typeof parsed?.required_agent_id === "string" ? parsed.required_agent_id : "";
  const agents = [...new Map((fleet.data?.pages.flatMap((page) => page.agents) ?? []).map((agent) => [agent.id, agent])).values()];
  const hosts = agents.filter((agent) => agent.roles?.includes(agentRole) && !agent.offboarded_at);
  const copy =
    agentRole === "network"
      ? { label: t("connectors.relay.label"), help: t("connectors.relay.help"), loading: t("connectors.relay.loading"), choose: t("connectors.relay.choose") }
      : { label: t("connectors.host.label"), help: t("connectors.host.help"), loading: t("connectors.host.loading"), choose: t("connectors.host.choose") };
  return (
    <div className="grid gap-2">
      <Field
        label={copy.label}
        description={copy.help}
        required={required}
        error={fleet.error?.message ?? (!parsed ? t("connectors.host.invalidConfig") : undefined)}
      >
        {(control) => (
          <Select
            {...control}
            value={selected}
            required={required}
            disabled={!parsed || fleet.isPending}
            onChange={(event) => onChange(JSON.stringify({ ...parsed, required_agent_id: event.target.value }, null, 2))}
          >
            <option value="">{fleet.isPending ? copy.loading : copy.choose}</option>
            {selected && !hosts.some((agent) => agent.id === selected) && <option value={selected}>{selected}</option>}
            {hosts.map((agent) => (
              <option key={agent.id} value={agent.id}>
                {agent.name} · {agent.status} · {agent.id}
              </option>
            ))}
          </Select>
        )}
      </Field>
      {fleet.hasNextPage && (
        <Button type="button" variant="outline" loading={fleet.isFetchingNextPage} onClick={() => void fleet.fetchNextPage()}>
          {t("connectors.host.more")}
        </Button>
      )}
      {fleet.isError && (
        <Button type="button" variant="outline" onClick={() => void fleet.refetch()}>
          {t("connectors.host.retry")}
        </Button>
      )}
    </div>
  );
}
