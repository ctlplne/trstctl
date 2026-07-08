import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { CheckCircle2, Info, TriangleAlert, X, XCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

type ToastKind = "error" | "info" | "success" | "warning";

export interface ToastInput {
  kind?: ToastKind;
  title: string;
  description?: string;
}

interface ToastRecord extends ToastInput {
  id: string;
  kind: ToastKind;
}

type ToastContextValue = {
  toast(input: ToastInput): void;
};

const ToastContext = createContext<ToastContextValue | null>(null);

const toastStyles: Record<ToastKind, string> = {
  error: "border-destructive/40 bg-destructive/10 text-destructive",
  info: "border-status-info/40 bg-status-info/10 text-status-info",
  success: "border-status-success/40 bg-status-success/10 text-status-success",
  warning: "border-status-warning/40 bg-status-warning/10 text-status-warning",
};

const toastIcons = {
  error: XCircle,
  info: Info,
  success: CheckCircle2,
  warning: TriangleAlert,
} satisfies Record<ToastKind, typeof Info>;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [records, setRecords] = useState<ToastRecord[]>([]);

  const remove = useCallback((id: string) => {
    setRecords((current) => current.filter((record) => record.id !== id));
  }, []);

  const toast = useCallback(
    (input: ToastInput) => {
      const id = `toast-${Date.now()}-${Math.random().toString(16).slice(2)}`;
      const record: ToastRecord = { kind: input.kind ?? "info", ...input, id };
      setRecords((current) => [...current.slice(-4), record]);
      window.setTimeout(() => remove(id), record.kind === "error" ? 6500 : 4000);
    },
    [remove],
  );

  const value = useMemo(() => ({ toast }), [toast]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <ol aria-live="polite" className="fixed right-4 top-16 z-50 grid w-[min(24rem,calc(100vw-2rem))] gap-2">
        {records.map((record) => {
          const Icon = toastIcons[record.kind];
          return (
            <li
              key={record.id}
              role={record.kind === "error" ? "alert" : "status"}
              aria-label={record.title}
              className={cn("flex items-start gap-3 rounded-panel border p-3 shadow-elevation2", toastStyles[record.kind])}
            >
              <Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-foreground">{record.title}</p>
                {record.description && <p className="mt-1 text-sm text-muted-foreground">{record.description}</p>}
              </div>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="h-7 w-7 shrink-0"
                onClick={() => remove(record.id)}
                aria-label="Dismiss notification"
              >
                <X className="h-4 w-4" aria-hidden="true" />
              </Button>
            </li>
          );
        })}
      </ol>
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const context = useContext(ToastContext);
  if (!context) throw new Error("useToast must be used inside ToastProvider");
  return context;
}
