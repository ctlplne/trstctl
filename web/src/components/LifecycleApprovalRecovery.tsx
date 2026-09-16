import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";
import { canRestartLifecycleApproval, type LifecycleApproval } from "@/lib/lifecycleCommand";

export function LifecycleApprovalRecovery({ approval, onReviewNew }: { approval: LifecycleApproval | null; onReviewNew: (requestId: string) => void }) {
  const { t } = useTranslation();
  if (!approval) return null;
  const closed = canRestartLifecycleApproval(approval);
  return (
    <div className="grid gap-2 text-sm">
      <p>{t(closed ? "identities.lifecycle.approvalClosed" : "identities.lifecycle.approvalPending")}</p>
      <Link to="/approvals" className="text-primary underline">
        {t("identities.lifecycle.openApprovals")}
      </Link>
      {closed && (
        <Button type="button" variant="outline" onClick={() => onReviewNew(approval.requestId)}>
          {t("identities.lifecycle.reviewNewRequest")}
        </Button>
      )}
    </div>
  );
}
