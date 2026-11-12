import type { UseFormReturn } from "react-hook-form";
import { Checkbox } from "@/components/ui/checkbox";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { useTranslation } from "@/i18n/I18nProvider";
import type { MessageKey } from "@/i18n/messages";
import type { SetupValues } from "./SourceSetup";

/** The secret stores beside the cloud secret managers: the code hosts' GitHub
 * Actions, Dependabot and Codespaces secrets and GitLab project, group and
 * instance variables (A173, OD-2), and the Infisical, Conjur, Akeyless and
 * Bitwarden Secrets Manager stores (OD-13). Their scope and sign-in fields
 * differ from the cloud providers', so they live beside the wizard rather
 * than inside its cloud section. */
export const secretStoreProviderIDs = ["github-actions", "gitlab-ci", "infisical", "conjur", "akeyless", "bitwarden-secrets-manager"] as const;

export function isSecretStoreProvider(provider: string): boolean {
  return (secretStoreProviderIDs as readonly string[]).includes(provider);
}

/** Whether a secret-store provider signs in with the shared token reference:
 * Conjur and Akeyless use their own credentials, and Infisical takes a token
 * or a Universal Auth client. */
export function secretStoreTokenRef(provider: string): "required" | "optional" | "hidden" {
  switch (provider) {
    case "conjur":
    case "akeyless":
      return "hidden";
    case "infisical":
      return "optional";
    default:
      return "required";
  }
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
    case "infisical":
      return {
        client_id: values.clientID,
        client_secret_ref: values.clientSecretRef,
        project: values.project,
        environments: listOf(values.environments),
        path_prefix: values.pathPrefix,
      };
    case "conjur":
      return { token_ref: "", account: values.conjurAccount, login: values.conjurLogin, api_key_ref: values.apiKeyRef, path_prefix: values.pathPrefix };
    case "akeyless":
      return { token_ref: "", client_id: values.clientID, client_secret_ref: values.clientSecretRef, path_prefix: values.pathPrefix };
    case "bitwarden-secrets-manager":
      return { identity_endpoint: values.identityEndpoint };
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
    case "infisical": {
      const client = Boolean(values.clientID) || Boolean(values.clientSecretRef);
      if (client && values.tokenRef) problems.push({ path: "tokenRef", key: "discovery.setup.validation.infisicalOneSignIn" });
      else if (!client && !values.tokenRef) problems.push({ path: "clientID", key: "discovery.setup.validation.infisicalSignIn" });
      else if (client && !values.clientID) problems.push({ path: "clientID", key: "discovery.setup.validation.clientID" });
      else if (client && !values.clientSecretRef) problems.push({ path: "clientSecretRef", key: "discovery.setup.validation.clientSecretRef" });
      if (listOf(values.environments).length > 0 && !values.project)
        problems.push({ path: "environments", key: "discovery.setup.validation.infisicalEnvironments" });
      break;
    }
    case "conjur":
      if (!values.endpoint) problems.push({ path: "endpoint", key: "discovery.setup.validation.conjurEndpoint" });
      if (!values.conjurAccount) problems.push({ path: "conjurAccount", key: "discovery.setup.validation.conjurAccount" });
      if (!values.conjurLogin) problems.push({ path: "conjurLogin", key: "discovery.setup.validation.conjurLogin" });
      if (!values.apiKeyRef) problems.push({ path: "apiKeyRef", key: "discovery.setup.validation.apiKeyRef" });
      break;
    case "akeyless":
      if (!values.clientID) problems.push({ path: "clientID", key: "discovery.setup.validation.accessID" });
      if (!values.clientSecretRef) problems.push({ path: "clientSecretRef", key: "discovery.setup.validation.akeylessAccessKeyRef" });
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
  if (provider === "infisical") {
    return (
      <div className="grid gap-4 lg:grid-cols-2">
        <Field label={t("discovery.setup.infisicalClientID")} description={t("discovery.setup.infisicalClientIDDescription")} error={errors.clientID?.message}>
          {(control) => <Input {...control} {...form.register("clientID")} className="font-mono text-xs" />}
        </Field>
        <Field
          label={t("discovery.setup.infisicalClientSecretRef")}
          description={t("discovery.setup.credentialRefDescription")}
          error={errors.clientSecretRef?.message}
        >
          {(control) => <Input {...control} {...form.register("clientSecretRef")} className="font-mono text-xs" />}
        </Field>
        <Field label={t("discovery.setup.infisicalProject")} description={t("discovery.setup.infisicalProjectDescription")} error={errors.project?.message}>
          {(control) => <Input {...control} {...form.register("project")} className="font-mono text-xs" />}
        </Field>
        <Field label={t("discovery.setup.infisicalEnvironments")} description={t("discovery.setup.listDescription")} error={errors.environments?.message}>
          {(control) => <Input {...control} {...form.register("environments")} />}
        </Field>
        <Field label={t("discovery.setup.infisicalPath")} description={t("discovery.setup.infisicalPathDescription")} error={errors.pathPrefix?.message}>
          {(control) => <Input {...control} {...form.register("pathPrefix")} className="font-mono text-xs" />}
        </Field>
      </div>
    );
  }
  if (provider === "conjur") {
    return (
      <div className="grid gap-4 lg:grid-cols-2">
        <Field label={t("discovery.setup.conjurAccount")} error={errors.conjurAccount?.message} required>
          {(control) => <Input {...control} {...form.register("conjurAccount")} />}
        </Field>
        <Field label={t("discovery.setup.conjurLogin")} description={t("discovery.setup.conjurLoginDescription")} error={errors.conjurLogin?.message} required>
          {(control) => <Input {...control} {...form.register("conjurLogin")} className="font-mono text-xs" />}
        </Field>
        <Field
          label={t("discovery.setup.conjurAPIKeyRef")}
          description={t("discovery.setup.credentialRefDescription")}
          error={errors.apiKeyRef?.message}
          required
        >
          {(control) => <Input {...control} {...form.register("apiKeyRef")} className="font-mono text-xs" />}
        </Field>
        <Field label={t("discovery.setup.conjurPath")} description={t("discovery.setup.conjurPathDescription")} error={errors.pathPrefix?.message}>
          {(control) => <Input {...control} {...form.register("pathPrefix")} className="font-mono text-xs" />}
        </Field>
      </div>
    );
  }
  if (provider === "akeyless") {
    return (
      <div className="grid gap-4 lg:grid-cols-2">
        <Field label={t("discovery.setup.akeylessAccessID")} error={errors.clientID?.message} required>
          {(control) => <Input {...control} {...form.register("clientID")} className="font-mono text-xs" />}
        </Field>
        <Field
          label={t("discovery.setup.akeylessAccessKeyRef")}
          description={t("discovery.setup.credentialRefDescription")}
          error={errors.clientSecretRef?.message}
          required
        >
          {(control) => <Input {...control} {...form.register("clientSecretRef")} className="font-mono text-xs" />}
        </Field>
        <Field label={t("discovery.setup.akeylessFolder")} description={t("discovery.setup.akeylessFolderDescription")} error={errors.pathPrefix?.message}>
          {(control) => <Input {...control} {...form.register("pathPrefix")} className="font-mono text-xs" />}
        </Field>
      </div>
    );
  }
  if (provider === "bitwarden-secrets-manager") {
    return (
      <div className="grid gap-4 lg:grid-cols-2">
        <Field
          label={t("discovery.setup.bitwardenIdentity")}
          description={t("discovery.setup.bitwardenIdentityDescription")}
          error={errors.identityEndpoint?.message}
        >
          {(control) => <Input {...control} {...form.register("identityEndpoint")} className="font-mono text-xs" />}
        </Field>
        <p className="text-sm text-muted-foreground lg:col-span-2">{t("discovery.setup.bitwardenTokenNote")}</p>
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
