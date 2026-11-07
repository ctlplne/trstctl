import { lazy, Suspense } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Eyebrow } from "@/components/typography";
import { Button } from "@/components/ui/button";
import { beginLogin, beginSAMLLogin, beginKerberosLogin, beginNTLMLogin, useAuth } from "@/auth/AuthProvider";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { BrandMark } from "@/components/BrandMark";
import { ErrorState } from "@/components/StatePrimitives";
import { translateNow } from "@/i18n/I18nProvider";

const LDAPLoginForm = lazy(() => import("./login/LDAPLoginForm"));

export function Login() {
  const { oidcAvailable, samlAvailable, ldapAvailable, kerberosAvailable, ntlmAvailable, ldapPasswordChangeAvailable, previewAvailable, startPreview } =
    useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const needsTenantAccess = searchParams.get("error") === "tenant_access_not_configured";
  // A277: a fresh sign-in offers only the methods that can prove one — the
  // identity provider asked to sign the person in again, or the directory
  // password typed now. SAML, Kerberos and NTLM reuse an earlier sign-in.
  const reauth = searchParams.get("reauth") === "1";
  const reauthNotProven = reauth && searchParams.get("error") === "reauthentication_not_proven";
  const showSAML = samlAvailable && !reauth;
  const showKerberos = kerberosAvailable && !reauth;
  const showNTLM = ntlmAvailable && !reauth;
  const browserLoginAvailable = oidcAvailable || showSAML || ldapAvailable || showKerberos || showNTLM;

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
            <CardTitle>
              {translateNow(reauth ? "auth.login.reauthTitle" : browserLoginAvailable ? "auth.login.title" : "auth.browserLoginDisabled.title")}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {needsTenantAccess && (
              <div className="mb-4">
                <ErrorState title={translateNow("auth.login.tenantAccessTitle")}>{translateNow("auth.login.tenantAccessBody")}</ErrorState>
              </div>
            )}
            {reauthNotProven && (
              <div className="mb-4">
                <ErrorState title={translateNow("auth.login.reauthNotProvenTitle")}>{translateNow("auth.login.reauthNotProvenBody")}</ErrorState>
              </div>
            )}
            <p className="mb-4 text-body text-muted-foreground">
              {translateNow(
                reauth
                  ? browserLoginAvailable
                    ? "auth.login.reauthBody"
                    : "auth.login.reauthUnavailable"
                  : browserLoginAvailable
                    ? "auth.login.body"
                    : "auth.browserLoginDisabled.body",
              )}
            </p>
            {oidcAvailable && (
              <Button className="min-h-11 w-full" onClick={() => beginLogin(searchParams.get("return_to") ?? undefined, { reauth })}>
                {translateNow("auth.login.action")}
              </Button>
            )}
            {showSAML && (
              <Button
                className="mt-3 min-h-11 w-full"
                variant={oidcAvailable ? "outline" : "default"}
                onClick={() => beginSAMLLogin(searchParams.get("return_to") ?? undefined)}
              >
                {translateNow("auth.saml.action")}
              </Button>
            )}
            {showKerberos && (
              <Button
                className="mt-3 min-h-11 w-full"
                variant={oidcAvailable || showSAML ? "outline" : "default"}
                onClick={() => beginKerberosLogin(searchParams.get("return_to") ?? undefined)}
              >
                {translateNow("auth.kerberos.action")}
              </Button>
            )}
            {showNTLM && (
              <Button
                className="mt-3 min-h-11 w-full"
                variant={oidcAvailable || showSAML || showKerberos ? "outline" : "default"}
                onClick={() => beginNTLMLogin(searchParams.get("return_to") ?? undefined)}
              >
                {translateNow("auth.ntlm.action")}
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
                <LDAPLoginForm
                  returnTo={searchParams.get("return_to") ?? undefined}
                  secondary={oidcAvailable || showSAML || showKerberos || showNTLM}
                  passwordChange={ldapPasswordChangeAvailable}
                />
              </Suspense>
            )}
            {previewAvailable && !reauth && (
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
