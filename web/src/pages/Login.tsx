import { useNavigate } from "react-router-dom";
import { Eyebrow } from "@/components/typography";
import { Button } from "@/components/ui/button";
import { beginLogin, useAuth } from "@/auth/AuthProvider";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { BrandMark } from "@/components/BrandMark";
import { translateNow } from "@/i18n/I18nProvider";

export function Login() {
  const { oidcAvailable, previewAvailable, startPreview } = useAuth();
  const navigate = useNavigate();

  function enterPreview() {
    startPreview();
    navigate("/");
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-muted/30 p-6">
      <div className="w-full max-w-sm space-y-6">
        <div className="flex flex-col items-center gap-3 text-center">
          <BrandMark size="md" />
          <div>
            <Eyebrow as="p">{translateNow("auth.login.eyebrow")}</Eyebrow>
            <h1 className="text-heading font-semibold tracking-tight">{translateNow("source.trstctl.74de2c6ee4")}</h1>
          </div>
        </div>

        <Card className="border-border/90 shadow-elevation1">
          <CardHeader>
            <CardTitle>{translateNow(oidcAvailable ? "auth.login.title" : "auth.browserLoginDisabled.title")}</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="mb-4 text-body text-muted-foreground">
              {translateNow(oidcAvailable ? "auth.login.body" : "auth.browserLoginDisabled.body")}
            </p>
            {oidcAvailable && (
              <Button className="min-h-11 w-full" onClick={beginLogin}>
                {translateNow("auth.login.action")}
              </Button>
            )}
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
