import { useNavigate } from "react-router-dom";
import { Eyebrow } from "@/components/typography";
import { Button } from "@/components/ui/button";
import { beginLogin, useAuth } from "@/auth/AuthProvider";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { translateNow } from "@/i18n/I18nProvider";

export function Login() {
  const { previewAvailable, startPreview } = useAuth();
  const navigate = useNavigate();

  function enterPreview() {
    startPreview();
    navigate("/");
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-muted/30 p-6">
      <div className="w-full max-w-sm space-y-6">
        <div className="flex flex-col items-center gap-3 text-center">
          <span aria-hidden="true" className="grid h-12 w-12 place-items-center rounded-panel bg-brand-accent text-brand-accent-foreground shadow-elevation2">
            <svg viewBox="0 0 32 32" className="h-7 w-7" fill="none">
              <path d="M8 11h16M16 6v20M11 21l5 4 5-4" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
              <circle cx="16" cy="16" r="4.2" stroke="currentColor" strokeWidth="1.8" />
            </svg>
          </span>
          <div>
            <Eyebrow as="p" className="font-mono font-medium tracking-wider text-brand-accent">
              {translateNow("source.machine.credential.access.bb586fcf38")}
            </Eyebrow>
            <h1 className="text-heading font-semibold tracking-tight">{translateNow("source.trstctl.74de2c6ee4")}</h1>
          </div>
        </div>

        <Card className="shadow-elevation2">
          <CardHeader>
            <CardTitle>{translateNow("source.sign.in.bfd402b2f6")}</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="mb-4 text-body text-muted-foreground">{translateNow("source.authenticate.with.your.organization.s.iden.c19821f6a0")}</p>
            <Button className="w-full" onClick={beginLogin}>
              {translateNow("source.sign.in.with.sso.73e984e9b4")}
            </Button>
            {previewAvailable && (
              <div className="mt-4 border-t border-border pt-4">
                <p className="mb-3 text-caption text-muted-foreground">{translateNow("source.preview.uses.sample.data.in.this.browser.a.7b39b478d2")}</p>
                <Button className="w-full" variant="outline" onClick={enterPreview}>
                  {translateNow("source.preview.ui.without.backend.ad12297cd6")}
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </main>
  );
}
