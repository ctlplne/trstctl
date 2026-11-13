import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import type { DiscoveryFinding } from "@/lib/api";

type AnnotationState = { status?: string; detail?: string; provider_ref?: string };

function text(value: unknown): string {
  return typeof value === "string" ? value : "";
}

// A174: a credential a third-party scan found in a Slack export, a Jira
// export, a CI log or a container image can be written back where it was
// seen (a thread reply, an issue comment, a commit status, a referrer), so
// the people there know to rotate it. The section names the place and shows
// what the provider confirmed.
export function FindingAnnotation({ finding, busy, onAnnotate }: { finding: DiscoveryFinding; busy: boolean; onAnnotate: () => Promise<void> }) {
  const { t } = useTranslation();
  const meta = (finding.metadata ?? {}) as Record<string, unknown>;
  const object = (meta.provider_object ?? {}) as Record<string, unknown>;
  // A174-L5: a first-party GitHub repository scan writes back through code scanning.
  const repositoryFile = text(object.kind) === "repository_file";
  if (finding.kind !== "leaked_secret" || (meta.capability !== "CAP-SCAN-04" && !repositoryFile)) return null;
  const provider = text(meta.annotation_provider);
  const actions = (meta.provider_actions ?? {}) as Record<string, AnnotationState>;
  const state = actions.annotate;
  const place =
    (repositoryFile
      ? [[text(object.path), text(object.line)].filter(Boolean).join(":"), [text(object.repo), text(object.commit_sha)].filter(Boolean).join("@")]
          .filter(Boolean)
          .join(" ")
      : "") ||
    text(object.issue_key) ||
    [text(object.channel), text(object.message_ts)].filter(Boolean).join(" ") ||
    [text(object.repo), text(object.commit_sha)].filter(Boolean).join("@") ||
    [text(object.repository), text(object.digest)].filter(Boolean).join("@");
  return (
    <section aria-labelledby="finding-annotation-heading" className="rounded-control border border-border p-3 text-sm">
      <h3 id="finding-annotation-heading" className="font-medium">
        {t("discovery.findings.annotation.heading")}
      </h3>
      {provider && place ? (
        <>
          <p className="mt-1 text-muted-foreground">{t("discovery.findings.annotation.where", { provider, place })}</p>
          {state?.status ? <p className="mt-2">{t("discovery.findings.annotation.state", { status: state.status, detail: state.detail ?? "" })}</p> : null}
          <Button type="button" size="sm" variant="outline" className="mt-3" disabled={busy} onClick={() => void onAnnotate()}>
            {t("discovery.findings.annotation.annotate", { provider })}
          </Button>
        </>
      ) : (
        <p className="mt-1 text-muted-foreground">{t("discovery.findings.annotation.unavailable")}</p>
      )}
    </section>
  );
}
