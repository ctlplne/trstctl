import type { UseFormReturn } from "react-hook-form";
import { Checkbox } from "@/components/ui/checkbox";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { useTranslation } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";
import type { SetupValues } from "./SourceSetup";

/** The code-host secret stores beside the cloud secret managers (A173): GitHub's
 * Actions, Dependabot and Codespaces secrets and GitLab's project, group and
 * instance variables (OD-2). Their scope fields differ from the cloud
 * providers', so they live beside the wizard rather than inside its cloud
 * section. */
export const secretStoreProviderIDs = ["github-actions", "gitlab-ci"] as const;

export function isSecretStoreProvider(provider: string): boolean {
  return (secretStoreProviderIDs as readonly string[]).includes(provider);
}

function listOf(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

/** The GitHub secret stores chosen for the repository and the organization. */
function githubStores(values: SetupValues): string[] {
  return [values.githubActions ? "actions" : "", values.githubDependabot ? "dependabot" : "", values.githubCodespaces ? "codespaces" : ""].filter(Boolean);
}

/** The provider's own scope fields, ready to merge into the provider config. */
export function secretStoreScope(values: SetupValues): Record<string, unknown> {
  switch (values.provider) {
    case "github-actions": {
      const stores = githubStores(values);
      return {
        owner: values.owner,
        repo: values.repo,
        environments: listOf(values.environments),
        org: values.org,
        // Actions alone is the provider's default, so the config names the
        // stores only when the choice differs from it.
        stores: stores.length === 1 && stores[0] === "actions" ? [] : stores,
        user_codespaces: values.githubUserCodespaces,
      };
    }
    case "gitlab-ci":
      return { project: values.project, group: values.group, instance: values.gitlabInstance };
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
      if (!values.repo && !values.org && !values.githubUserCodespaces) problems.push({ path: "repo", key: "discovery.setup.validation.githubScope" });
      if ((values.repo || values.org) && githubStores(values).length === 0)
        problems.push({ path: "githubActions", key: "discovery.setup.validation.githubStores" });
      if (listOf(values.environments).length > 0 && !values.repo) problems.push({ path: "environments", key: "discovery.setup.validation.githubEnvironments" });
      else if (listOf(values.environments).length > 0 && !values.githubActions)
        problems.push({ path: "environments", key: "discovery.setup.validation.githubEnvironmentsActions" });
      if (values.inspectContent) problems.push({ path: "provider", key: "discovery.setup.validation.githubNoContent" });
      break;
    case "gitlab-ci":
      if (!values.project && !values.group && !values.gitlabInstance) problems.push({ path: "project", key: "discovery.setup.validation.gitlabScope" });
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
        <fieldset
          className="rounded-panel border border-border p-4 lg:col-span-2"
          aria-describedby={errors.githubActions?.message ? "source-setup-github-types-help source-setup-github-types-error" : "source-setup-github-types-help"}
        >
          <legend className="px-1 text-sm font-medium">{t("discovery.setup.githubStores")}</legend>
          <p id="source-setup-github-types-help" className="text-sm text-muted-foreground">
            {t("discovery.setup.githubStoresDescription")}
          </p>
          <div className="mt-3 flex flex-wrap gap-x-6 gap-y-2">
            {(
              [
                ["githubActions", "discovery.setup.githubStoreActions"],
                ["githubDependabot", "discovery.setup.githubStoreDependabot"],
                ["githubCodespaces", "discovery.setup.githubStoreCodespaces"],
              ] as const
            ).map(([name, label]) => (
              <label key={name} htmlFor={`source-setup-${name}`} className="flex items-center gap-2 text-sm">
                <Checkbox {...form.register(name)} id={`source-setup-${name}`} />
                {t(label)}
              </label>
            ))}
          </div>
          {errors.githubActions?.message ? (
            <p id="source-setup-github-types-error" className="mt-2 text-caption font-medium text-risk-critical">
              {errors.githubActions.message}
            </p>
          ) : null}
        </fieldset>
        <label htmlFor="source-setup-githubUserCodespaces" className="flex items-start gap-3 text-sm lg:col-span-2">
          <Checkbox {...form.register("githubUserCodespaces")} id="source-setup-githubUserCodespaces" className="mt-0.5" />
          <span>
            <strong>{t("discovery.setup.githubUserCodespaces")}</strong>
            <span className="mt-0.5 block text-muted-foreground">{t("discovery.setup.githubUserCodespacesDescription")}</span>
          </span>
        </label>
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
        <label htmlFor="source-setup-gitlabInstance" className="flex items-start gap-3 text-sm lg:col-span-2">
          <Checkbox {...form.register("gitlabInstance")} id="source-setup-gitlabInstance" className="mt-0.5" />
          <span>
            <strong>{t("discovery.setup.gitlabInstance")}</strong>
            <span className="mt-0.5 block text-muted-foreground">{t("discovery.setup.gitlabInstanceDescription")}</span>
          </span>
        </label>
      </div>
    );
  }
  return null;
}
