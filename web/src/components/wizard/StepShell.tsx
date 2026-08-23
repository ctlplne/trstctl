import { useEffect, useState, type ReactNode } from "react";
import { ArrowLeft, ArrowRight, CheckCircle2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { translateNow } from "@/i18n/I18nProvider";

export type CarouselStep = {
  id: string;
  label: string;
  description: string;
};

export function StepShell({
  children,
  currentIndex,
  nextDisabled,
  nextLabel,
  onNext,
  onPrevious,
  steps,
}: {
  children: ReactNode;
  currentIndex: number;
  nextDisabled?: boolean;
  nextLabel?: string;
  onNext?: () => void;
  onPrevious?: () => void;
  steps: CarouselStep[];
}) {
  const reducedMotion = usePrefersReducedMotion();
  const currentStep = steps[currentIndex];
  const progress = Math.round(((currentIndex + 1) / steps.length) * 100);
  const compactSteps = steps.map((step, index) => ({ step, index })).filter(({ index }) => Math.abs(index - currentIndex) <= 1);

  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      const target = event.target instanceof HTMLElement ? event.target : null;
      if (target?.closest("input, textarea, select, [contenteditable='true']")) return;
      if (event.key === "ArrowLeft" && currentIndex > 0 && onPrevious) {
        event.preventDefault();
        onPrevious();
      }
      if (event.key === "ArrowRight" && onNext && !nextDisabled) {
        event.preventDefault();
        onNext();
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [currentIndex, nextDisabled, onNext, onPrevious]);

  return (
    <section aria-label={translateNow("source.onboarding.carousel.282df6ade1")} className="ui-panel overflow-hidden">
      <div className="border-b border-border p-comfortable">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="text-caption font-medium text-muted-foreground">
              {translateNow("source.step.8e6a6cca7a")} {currentIndex + 1} {translateNow("source.of.28391d3bc6")} {steps.length}
            </p>
            <h2 className="mt-1 text-title font-semibold">{currentStep?.label}</h2>
            <p className="mt-1 max-w-2xl text-sm text-muted-foreground">{currentStep?.description}</p>
          </div>
          <p className="font-mono text-caption text-muted-foreground">{progress}%</p>
        </div>
        <ol
          className="mt-5 hidden gap-2 sm:grid sm:grid-cols-4"
          aria-label={translateNow("source.onboarding.progress.ad8a0dac00")}
          data-testid="full-step-progress"
        >
          {steps.map((step, index) => {
            const state = index < currentIndex ? "done" : index === currentIndex ? "current" : "upcoming";
            return (
              <li key={step.id} aria-current={state === "current" ? "step" : undefined} className="min-w-0">
                <div className={cn("flex items-center gap-2 rounded-control border px-2 py-2 text-sm", stepStateClass(state))}>
                  <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-current">
                    {state === "done" ? <CheckCircle2 className="h-4 w-4" aria-hidden="true" /> : index + 1}
                  </span>
                  <span className="truncate">{step.label}</span>
                </div>
              </li>
            );
          })}
        </ol>
        <ol className="mt-4 grid gap-1 sm:hidden" aria-label={translateNow("source.onboarding.progress.ad8a0dac00")} data-testid="compact-step-progress">
          {compactSteps.map(({ step, index }) => {
            const state = index < currentIndex ? "done" : index === currentIndex ? "current" : "upcoming";
            return (
              <li
                key={`compact-${step.id}`}
                aria-current={state === "current" ? "step" : undefined}
                className={cn(
                  "flex min-w-0 items-center gap-2 border-s-2 px-2 py-1.5 text-sm",
                  state === "current" ? "border-primary bg-primary/10 text-foreground" : "border-border text-muted-foreground",
                )}
              >
                <span className="w-5 shrink-0 text-center text-caption tabular-nums" aria-hidden="true">
                  {state === "done" ? "✓" : index + 1}
                </span>
                <span className="min-w-0 flex-1 truncate">{step.label}</span>
              </li>
            );
          })}
        </ol>
      </div>

      <div
        aria-live="polite"
        data-testid="onboarding-slide"
        data-motion={reducedMotion ? "reduced" : "animated"}
        className={cn("p-comfortable", reducedMotion ? "" : "transition-[opacity,transform] duration-300 ease-out")}
      >
        {children}
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border p-comfortable">
        <Button type="button" variant="outline" onClick={onPrevious} disabled={currentIndex === 0 || !onPrevious}>
          <ArrowLeft className="h-4 w-4" aria-hidden="true" />
          {translateNow("source.previous.a57b08a480")}
        </Button>
        {onNext ? (
          <Button type="button" onClick={onNext} disabled={nextDisabled}>
            {nextLabel ?? translateNow("source.next.1ff57a29d7")}
            <ArrowRight className="h-4 w-4" aria-hidden="true" />
          </Button>
        ) : null}
      </div>
    </section>
  );
}

function stepStateClass(state: "current" | "done" | "upcoming") {
  if (state === "done") return "border-status-success/40 bg-status-success/10 text-status-success";
  if (state === "current") return "border-brand-accent/50 bg-brand-accent/10 text-foreground";
  return "border-border bg-muted/40 text-muted-foreground";
}

function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(() => {
    if (typeof window === "undefined" || !window.matchMedia) return false;
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  });

  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return undefined;
    const media = window.matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => setReduced(media.matches);
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, []);

  return reduced;
}
