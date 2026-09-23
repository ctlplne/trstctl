import { lazy, Suspense } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Eyebrow } from "@/components/typography";
import { Button } from "@/components/ui/button";
import { beginLogin, beginSAMLLogin, useAuth } from "@/auth/AuthProvider";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { BrandMark } from "@/components/BrandMark";
import { ErrorState } from "@/components/StatePrimitives";
import { translateNow } from "@/i18n/I18nProvider";

const LDAPLoginForm = lazy(() => import("./login/LDAPLoginForm"));

export function Login() {
  const { oidcAvailable, samlAvailable, ldapAvailable, previewAvailable, startPreview } = useAuth();
  const browserLoginAvailable = oidcAvailable || samlAvailable || ldapAvailable;
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const needsTenantAccess = searchParams.get("error") === "tenant_access_not_configured";

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
            <CardTitle>{translateNow(browserLoginAvailable ? "auth.login.title" : "auth.browserLoginDisabled.title")}</CardTitle>
          </CardHeader>
          <CardContent>
            {needsTenantAccess && (
              <div className="mb-4">
                <ErrorState title={translateNow("auth.login.tenantAccessTitle")}>{translateNow("auth.login.tenantAccessBody")}</ErrorState>
              </div>
            )}
            <p className="mb-4 text-body text-muted-foreground">{translateNow(browserLoginAvailable ? "auth.login.body" : "auth.browserLoginDisabled.body")}</p>
            {oidcAvailable && (
              <Button className="min-h-11 w-full" onClick={() => beginLogin(searchParams.get("return_to") ?? undefined)}>
                {translateNow("auth.login.action")}
              </Button>
            )}
            {samlAvailable && (
              <Button
                className="mt-3 min-h-11 w-full"
                variant={oidcAvailable ? "outline" : "default"}
                onClick={() => beginSAMLLogin(searchParams.get("return_to") ?? undefined)}
              >
                {translateNow("auth.saml.action")}
              </Button>
            )}
            {ldapAvailable && (
              <Suspense
                fallback={
                  <p role="status" className="mt-4 text-body">
                    {translateNow("app.loading")}
                  </p>
                }
              >
                <LDAPLoginForm returnTo={searchParams.get("return_to") ?? undefined} secondary={oidcAvailable || samlAvailable} />
              </Suspense>
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
