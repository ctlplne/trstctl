import { useEffect, useState } from "react";
import { cn } from "@/lib/utils";
import { StatusBadge } from "@/components/StatusBadge";
import { riskBand } from "@/lib/statusVocab";
import { api, type RiskQuery } from "@/lib/api";

export function RiskScore({ score, showValue = true, className }: { score: number; showValue?: boolean; className?: string }) {
  const band = riskBand(score);
  return (
    <span className={cn("inline-flex items-center gap-1.5", className)}>
      <StatusBadge vocabulary="risk" value={band} />
      {showValue ? <span className="text-caption tabular-nums text-muted-foreground">{Math.round(score)}</span> : null}
    </span>
  );
}

export type RiskItem = Awaited<ReturnType<typeof api.risk>>[number];

export function useRisk(options?: RiskQuery): { loading: boolean; data: RiskItem[]; error: string | null } {
  const [state, setState] = useState<{ loading: boolean; data: RiskItem[]; error: string | null }>({ loading: true, data: [], error: null });
  const sort = options?.sort;
  const minScore = options?.minScore;
  const privilege = options?.privilege;
  const owner = options?.owner;
  useEffect(() => {
    let active = true;
    setState((current) => ({ ...current, loading: true }));
    api
      .risk({ sort, minScore, privilege, owner })
      .then((data) => {
        if (active) setState({ loading: false, data, error: null });
      })
      .catch((err: unknown) => {
        if (active) setState({ loading: false, data: [], error: String(err) });
      });
    return () => {
      active = false;
    };
  }, [sort, minScore, privilege, owner]);
  return state;
}
