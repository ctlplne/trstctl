import type { UseFormReturn } from "react-hook-form";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { useTranslation } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";
import type { SetupValues } from "./SourceSetup";

/** The code-host and secret-store providers beyond the cloud secret managers
 * (A173). Their scope fields differ from the cloud providers', so they live
 * beside the wizard rather than inside its cloud section. */
export const secretStoreProviderIDs = ["github-actions", "gitlab-ci", "1password-connect", "doppler"] as const;

export function isSecretStoreProvider(provider: string): boolean {
  return (secretStoreProviderIDs as readonly string[]).includes(provider);
}

function listOf(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

/** The provider's own scope fields, ready to merge into the provider config. */
export function secretStoreScope(values: SetupValues): Record<string, unknown> {
  switch (values.provider) {
    case "github-actions":
      return { owner: values.owner, repo: values.repo, environments: listOf(values.environments), org: values.org };
    case "gitlab-ci":
      return { project: values.project, group: values.group };
    case "1password-connect":
      return { vaults: listOf(values.vaults) };
    case "doppler":
      return { project: values.project, configs: listOf(values.configs) };
    default:
      return {};
  }
}

/** The reasons a secret-store provider's scope cannot be saved, by field. */
export function secretStoreScopeProblems(values: SetupValues): Array<{ path: keyof SetupValues; key: MessageKey }> {
  const problems: Array<{ path: keyof SetupValues; key: MessageKey }> = [];
  switch (values.provider) {
    case "github-actions":
      if (Boolean(values.owner) !== Boolean(values.repo))
        problems.push({ path: values.owner ? "repo" : "owner", key: "discovery.setup.validation.githubRepo" });
      if (!values.repo && !values.org) problems.push({ path: "repo", key: "discovery.setup.validation.githubScope" });
      if (listOf(values.environments).length > 0 && !values.repo) problems.push({ path: "environments", key: "discovery.setup.validation.githubEnvironments" });
      if (values.inspectContent) problems.push({ path: "provider", key: "discovery.setup.validation.githubNoContent" });
      break;
    case "gitlab-ci":
      if (!values.project && !values.group) problems.push({ path: "project", key: "discovery.setup.validation.gitlabScope" });
      break;
    case "1password-connect":
      if (!values.endpoint) problems.push({ path: "endpoint", key: "discovery.setup.validation.connectEndpoint" });
      break;
    case "doppler":
      if (listOf(values.configs).length > 0 && !values.project) problems.push({ path: "project", key: "discovery.setup.validation.dopplerProject" });
      break;
  }
  return problems;
}

export function SecretStoreFields({ form, provider }: { form: UseFormReturn<SetupValues>; provider: string }) {
  const { t } = useTranslation();
  const errors = form.formState.errors;
  if (provider === "github-actions") {
    return (
      <div className="grid gap-4 lg:grid-cols-2">
        <Field label={t("discovery.setup.githubOwner")} error={errors.owner?.message}>
          {(control) => <Input {...control} {...form.register("owner")} />}
        </Field>
        <Field label={t("discovery.setup.githubRepo")} error={errors.repo?.message}>
          {(control) => <Input {...control} {...form.register("repo")} />}
        </Field>
        <Field label={t("discovery.setup.githubEnvironments")} description={t("discovery.setup.listDescription")} error={errors.environments?.message}>
          {(control) => <Input {...control} {...form.register("environments")} />}
        </Field>
        <Field label={t("discovery.setup.githubOrg")} error={errors.org?.message}>
          {(control) => <Input {...control} {...form.register("org")} />}
        </Field>
        <p className="text-sm text-muted-foreground lg:col-span-2">{t("discovery.setup.githubMetadataOnly")}</p>
      </div>
    );
  }
  if (provider === "gitlab-ci") {
    return (
      <div className="grid gap-4 lg:grid-cols-2">
        <Field label={t("discovery.setup.gitlabProject")} description={t("discovery.setup.gitlabPathDescription")} error={errors.project?.message}>
          {(control) => <Input {...control} {...form.register("project")} />}
        </Field>
        <Field label={t("discovery.setup.gitlabGroup")} description={t("discovery.setup.gitlabPathDescription")} error={errors.group?.message}>
          {(control) => <Input {...control} {...form.register("group")} />}
        </Field>
      </div>
    );
  }
  if (provider === "1password-connect") {
    return (
      <Field label={t("discovery.setup.onePasswordVaults")} description={t("discovery.setup.onePasswordVaultsDescription")} error={errors.vaults?.message}>
        {(control) => <Input {...control} {...form.register("vaults")} />}
      </Field>
    );
  }
  if (provider === "doppler") {
    return (
      <div className="grid gap-4 lg:grid-cols-2">
        <Field label={t("discovery.setup.dopplerProject")} description={t("discovery.setup.dopplerProjectDescription")} error={errors.project?.message}>
          {(control) => <Input {...control} {...form.register("project")} />}
        </Field>
        <Field label={t("discovery.setup.dopplerConfigs")} description={t("discovery.setup.listDescription")} error={errors.configs?.message}>
          {(control) => <Input {...control} {...form.register("configs")} />}
        </Field>
      </div>
    );
  }
  return null;
}
