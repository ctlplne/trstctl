import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import { Field } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { ErrorState } from "@/components/StatePrimitives";
import { bootstrapApi } from "@/lib/bootstrapApi";
import { translateNow } from "@/i18n/I18nProvider";

function returnPath(value?: string): string {
  if (
    !value ||
    new TextEncoder().encode(value).length > 4096 ||
    !value.startsWith("/") ||
    value.startsWith("//") ||
    value.includes("\\") ||
    Array.from(value).some((character) => character.charCodeAt(0) <= 0x20)
  )
    return "/";
  try {
    // Validate escaped bytes too: URL.pathname alone leaves %61uth and
    // encoded separators untouched. Preserve the original query and fragment.
    const decoded = decodeURIComponent(value);
    if (Array.from(decoded).some((character) => character.charCodeAt(0) < 0x20 || character.charCodeAt(0) === 0x7f)) return "/";
    const url = new URL(value, window.location.origin);
    const path = decodeURIComponent(url.pathname);
    if (url.origin !== window.location.origin || path.startsWith("//") || path.includes("\\")) return "/";
    const normalized: string[] = [];
    for (const segment of new URL(path, window.location.origin).pathname.split("/")) {
      if (segment === "..") normalized.pop();
      else if (segment && segment !== ".") normalized.push(segment);
    }
    const destination = "/" + normalized.join("/").toLowerCase();
    if (destination === "/login" || destination === "/auth" || destination.startsWith("/auth/")) return "/";
    return url.pathname + url.search + url.hash;
  } catch {
    // Malformed percent escapes must not strand an authenticated operator.
    return "/";
  }
}

export default function LDAPLoginForm({ returnTo, secondary = false }: { returnTo?: string; secondary?: boolean }) {
  const schema = z.object({
    username: z.string().trim().min(1, translateNow("auth.ldap.usernameRequired")),
    // Password whitespace belongs to the credential; never trim it.
    password: z.string().min(1, translateNow("auth.ldap.passwordRequired")),
  });
  const {
    register,
    handleSubmit,
    resetField,
    formState: { errors, isSubmitting },
  } = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: { username: "", password: "" },
  });
  const [submitError, setSubmitError] = useState<string | null>(null);
  const submit = handleSubmit(async (values) => {
    setSubmitError(null);
    let authenticated = false;
    try {
      // The server sets the session and redirects to HTML, not a JSON login
      // response. Read /auth/me before navigating; HTTP success alone is not
      // evidence that authentication established an operator session.
      const response = await fetch("/auth/ldap/login", {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(values),
      });
      if (!response.ok) {
        setSubmitError(
          translateNow(
            response.status === 401
              ? "auth.ldap.rejected"
              : response.status === 403
                ? "auth.login.tenantAccessBody"
                : response.status === 429
                  ? "auth.ldap.rateLimited"
                  : "auth.ldap.unavailable",
          ),
        );
        return;
      }
      await bootstrapApi.me();
      authenticated = true;
    } catch {
      setSubmitError(translateNow("auth.ldap.unavailable"));
    } finally {
      resetField("password", { defaultValue: "" });
      values.password = "";
    }
    // Reload to bootstrap all session-bound state from the verified session.
    if (authenticated) window.location.assign(returnPath(returnTo));
  });
  return (
    <form className="mt-4 space-y-4" onSubmit={submit} noValidate>
      <fieldset disabled={isSubmitting} className="space-y-4">
        <Field label={translateNow("auth.ldap.username")} error={errors.username?.message} required>
          {(control) => <Input {...control} {...register("username")} autoComplete="username" />}
        </Field>
        <Field label={translateNow("auth.ldap.password")} error={errors.password?.message} required>
          {(control) => <Input {...control} {...register("password")} type="password" autoComplete="current-password" />}
        </Field>
        {submitError && <ErrorState title={translateNow("auth.ldap.failed")}>{submitError}</ErrorState>}
        <Button type="submit" variant={secondary ? "outline" : "default"} className="min-h-11 w-full" loading={isSubmitting}>
          {translateNow("auth.ldap.action")}
        </Button>
      </fieldset>
    </form>
  );
}
