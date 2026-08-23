import { Component, type ReactNode } from "react";
import { BrandMark } from "@/components/BrandMark";
import { Button } from "@/components/ui/button";
import { useTranslation } from "@/i18n/I18nProvider";

interface AppErrorBoundaryProps {
  children: ReactNode;
  onReload?: () => void;
  onHome?: () => void;
}

interface AppErrorBoundaryState {
  failed: boolean;
}

/** Last-resort UI containment. A route bug must become a calm, recoverable
 * product state instead of a blank page. The panel deliberately omits the
 * exception text because API responses and route state can contain customer
 * identifiers; operators can collect the bounded, redacted support bundle. */
export class AppErrorBoundary extends Component<AppErrorBoundaryProps, AppErrorBoundaryState> {
  state: AppErrorBoundaryState = { failed: false };

  static getDerivedStateFromError(): AppErrorBoundaryState {
    return { failed: true };
  }

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <ErrorRecoveryPanel
        onReload={this.props.onReload ?? (() => window.location.reload())}
        onHome={this.props.onHome ?? (() => window.location.assign("/"))}
      />
    );
  }
}

function ErrorRecoveryPanel({ onHome, onReload }: { onHome: () => void; onReload: () => void }) {
  const { t } = useTranslation();
  return (
    <main className="grid min-h-dvh place-items-center bg-background p-6" aria-labelledby="app-error-heading">
      <section className="ui-panel grid w-full max-w-xl gap-5 p-comfortable">
        <div className="flex items-center gap-3">
          <BrandMark size="md" />
          <h1 id="app-error-heading" className="text-headline font-semibold">
            {t("app.error.heading")}
          </h1>
        </div>
        <p className="border-s-2 border-status-warning ps-3 text-body">{t("app.error.description")}</p>
        <div className="flex flex-wrap gap-2">
          <Button type="button" onClick={onReload}>
            {t("app.error.reload")}
          </Button>
          <Button type="button" variant="outline" onClick={onHome}>
            {t("nav.item.dashboard")}
          </Button>
        </div>
      </section>
    </main>
  );
}
