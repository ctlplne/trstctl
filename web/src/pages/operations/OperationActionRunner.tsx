import { useState } from "react";
import { Play } from "lucide-react";
import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import type { OperationLedgerDetail } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";
import { previewOperationAction, runOperationAction } from "@/lib/operationActionsApi";

type OperationAction = NonNullable<OperationLedgerDetail["actions"]>[number];

/** The review's outcome as the operator reads it: nothing blocking, or the
 * blockers the route's preview named. */
function reviewBlockers(preview: unknown): string[] {
  if (!preview || typeof preview !== "object") return [];
  const blockers = (preview as { blockers?: unknown }).blockers;
  return Array.isArray(blockers) ? blockers.filter((b): b is string => typeof b === "string") : [];
}

/** OperationActionRunner runs one ledger action in place (A245-L4): the
 * route's preview of the exact request first when the route has one, then that
 * request, through the route's own checks and approval. A refusal, an approval
 * the route waits for included, is shown as the route gave it. */
export function OperationActionRunner({ action, label, onDone }: { action: OperationAction; label: string; onDone: () => void }) {
  const { t } = useTranslation();
  const [stage, setStage] = useState<"idle" | "reviewing" | "reviewed" | "running" | "sent">("idle");
  const [blockers, setBlockers] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const { method, path, body, preview_path: previewPath } = action;
  if (!action.available || !method || !path || !body) return null;

  async function review() {
    setError(null);
    if (!previewPath) {
      setStage("reviewed");
      return;
    }
    setStage("reviewing");
    try {
      setBlockers(reviewBlockers(await previewOperationAction(previewPath, body)));
      setStage("reviewed");
    } catch (err) {
      setError(apiProblemMessage(err, t("operations.ledger.run.reviewFailed")));
      setStage("idle");
    }
  }

  async function run() {
    setError(null);
    setStage("running");
    try {
      await runOperationAction(method!, path!, body);
      setStage("sent");
      onDone();
    } catch (err) {
      setError(apiProblemMessage(err, t("operations.ledger.run.failed")));
      setStage("reviewed");
    }
  }

  return (
    <div className="mt-1 grid gap-2">
      {stage === "idle" || stage === "reviewing" ? (
        <div>
          <Button type="button" size="sm" variant="outline" disabled={stage === "reviewing"} onClick={() => void review()}>
            <Play className="h-4 w-4" aria-hidden="true" />
            {t(previewPath ? "operations.ledger.run.review" : "operations.ledger.run.prepare", { action: label })}
          </Button>
        </div>
      ) : null}
      {stage === "reviewed" || stage === "running" ? (
        <div className="grid gap-2">
          <p role="status" className="text-sm">
            {!previewPath
              ? t("operations.ledger.run.noReview", { scope: action.scope })
              : blockers.length === 0
                ? t("operations.ledger.run.ready")
                : t("operations.ledger.run.blocked", { blockers: blockers.join("; ") })}
          </p>
          <div className="flex flex-wrap gap-2">
            <Button type="button" size="sm" disabled={stage === "running"} onClick={() => void run()}>
              {t("operations.ledger.run.confirm", { action: label })}
            </Button>
            <Button type="button" size="sm" variant="ghost" disabled={stage === "running"} onClick={() => setStage("idle")}>
              {t("operations.ledger.run.cancel")}
            </Button>
          </div>
        </div>
      ) : null}
      {stage === "sent" ? (
        <p role="status" className="text-sm">
          {t("operations.ledger.run.sent", { action: label })}
        </p>
      ) : null}
      {error ? <ErrorState title={t("operations.ledger.run.failedTitle")}>{error}</ErrorState> : null}
    </div>
  );
}
