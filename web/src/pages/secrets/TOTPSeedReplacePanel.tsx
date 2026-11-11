import { useState } from "react";
import { KeyRound } from "lucide-react";
import { ErrorState } from "@/components/StatePrimitives";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { useTranslation } from "@/i18n/I18nProvider";
import { api } from "@/lib/api";
import { apiProblemMessage } from "@/lib/apiProblem";

// TOTPSeedReplacePanel replaces a TOTP provider's seed when the account's MFA
// is enrolled again (A239-L5): the new seed, as the identity provider shows
// it, and a code an authenticator made from it now. The server checks the code
// before it writes the seed as the next version of the provider's secret://
// reference; the seed is never shown back.
export function TOTPSeedReplacePanel({ provider }: { provider: string }) {
  const { t } = useTranslation();
  const [seed, setSeed] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [replaced, setReplaced] = useState<{ name: string; version: number } | null>(null);

  async function replace() {
    setBusy(true);
    setError(null);
    setReplaced(null);
    try {
      const meta = await api.replaceTOTPProviderSeed(provider, { seed, code });
      setReplaced({ name: meta.name, version: meta.version });
      setSeed("");
      setCode("");
    } catch (err) {
      setError(apiProblemMessage(err, t("secrets.dynamic.totpSeed.failed")));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("secrets.dynamic.totpSeed.title")}</CardTitle>
        <p className="text-sm text-muted-foreground">{t("secrets.dynamic.totpSeed.description")}</p>
      </CardHeader>
      <CardContent className="grid gap-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t("secrets.dynamic.totpSeed.seed")} description={t("secrets.dynamic.totpSeed.seedHelp")} required>
            {(field) => (
              <Input {...field} type="password" autoComplete="off" spellCheck={false} value={seed} onChange={(event) => setSeed(event.target.value)} />
            )}
          </Field>
          <Field label={t("secrets.dynamic.totpSeed.code")} description={t("secrets.dynamic.totpSeed.codeHelp")} required>
            {(field) => <Input {...field} inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(event) => setCode(event.target.value)} />}
          </Field>
        </div>
        <div>
          <Button type="button" variant="outline" disabled={busy || seed.trim() === "" || code.trim() === ""} onClick={() => void replace()}>
            <KeyRound className="h-4 w-4" aria-hidden="true" />
            {t("secrets.dynamic.totpSeed.replace")}
          </Button>
        </div>
        {error ? <ErrorState title={t("secrets.dynamic.totpSeed.failed")}>{error}</ErrorState> : null}
        {replaced ? (
          <p role="status" className="text-sm">
            {t("secrets.dynamic.totpSeed.replaced", { name: replaced.name, version: String(replaced.version) })}
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}
