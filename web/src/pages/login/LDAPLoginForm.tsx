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

/** LDAPPasswordChangeForm changes the directory password through
 * POST /auth/ldap/password after proving the current one (A81). */
function LDAPPasswordChangeForm({ username, required, onDone }: { username?: string; required?: boolean; onDone: () => void }) {
  const schema = z
    .object({
      username: z.string().trim().min(1, translateNow("auth.ldap.usernameRequired")),
      currentPassword: z.string().min(1, translateNow("auth.ldap.passwordRequired")),
      newPassword: z.string().min(1, translateNow("auth.ldap.passwordRequired")),
      confirmPassword: z.string(),
    })
    .refine((values) => values.newPassword === values.confirmPassword, {
      message: translateNow("auth.ldap.passwordMismatch"),
      path: ["confirmPassword"],
    });
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
    defaultValues: { username: username ?? "", currentPassword: "", newPassword: "", confirmPassword: "" },
  });
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [changed, setChanged] = useState(false);
  const submit = handleSubmit(async (values) => {
    setSubmitError(null);
    try {
      const response = await fetch("/auth/ldap/password", {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ username: values.username, current_password: values.currentPassword, new_password: values.newPassword }),
      });
      if (response.status === 204) {
        setChanged(true);
        return;
      }
      if (response.status === 422) {
        const problem = (await response.json().catch(() => null)) as { detail?: string } | null;
        setSubmitError(problem?.detail ?? translateNow("auth.ldap.passwordRefused"));
        return;
      }
      setSubmitError(
        translateNow(response.status === 401 ? "auth.ldap.rejected" : response.status === 429 ? "auth.ldap.rateLimited" : "auth.ldap.unavailable"),
      );
    } catch {
      setSubmitError(translateNow("auth.ldap.unavailable"));
    } finally {
      reset({ username: values.username, currentPassword: "", newPassword: "", confirmPassword: "" });
      values.currentPassword = "";
      values.newPassword = "";
      values.confirmPassword = "";
    }
  });
  if (changed) {
    return (
      <div className="mt-4 space-y-4" role="status">
        <p className="text-body">{translateNow("auth.ldap.passwordChanged")}</p>
        <Button type="button" variant="outline" className="min-h-11 w-full" onClick={onDone}>
          {translateNow("auth.ldap.backToSignIn")}
        </Button>
      </div>
    );
  }
  return (
    <form className="mt-4 space-y-4" onSubmit={submit} noValidate>
      {required && <ErrorState title={translateNow("auth.ldap.passwordChangeRequired")}>{translateNow("auth.ldap.passwordChangeRequiredBody")}</ErrorState>}
      <fieldset disabled={isSubmitting} className="space-y-4">
        <Field label={translateNow("auth.ldap.username")} error={errors.username?.message} required>
          {(control) => <Input {...control} {...register("username")} autoComplete="username" />}
        </Field>
        <Field label={translateNow("auth.ldap.currentPassword")} error={errors.currentPassword?.message} required>
          {(control) => <Input {...control} {...register("currentPassword")} type="password" autoComplete="current-password" />}
        </Field>
        <Field label={translateNow("auth.ldap.newPassword")} error={errors.newPassword?.message} required>
          {(control) => <Input {...control} {...register("newPassword")} type="password" autoComplete="new-password" />}
        </Field>
        <Field label={translateNow("auth.ldap.confirmPassword")} error={errors.confirmPassword?.message} required>
          {(control) => <Input {...control} {...register("confirmPassword")} type="password" autoComplete="new-password" />}
        </Field>
        {submitError && <ErrorState title={translateNow("auth.ldap.passwordChangeFailed")}>{submitError}</ErrorState>}
        <Button type="submit" className="min-h-11 w-full" loading={isSubmitting}>
          {translateNow("auth.ldap.changeAction")}
        </Button>
        <Button type="button" variant="outline" className="min-h-11 w-full" onClick={onDone}>
          {translateNow("auth.ldap.backToSignIn")}
        </Button>
      </fieldset>
    </form>
  );
}

export default function LDAPLoginForm({
  returnTo,
  secondary = false,
  passwordChange = false,
}: {
  returnTo?: string;
  secondary?: boolean;
  passwordChange?: boolean;
}) {
  const [changing, setChanging] = useState<{ username?: string; required: boolean } | null>(null);
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
        if (response.status === 403 && passwordChange) {
          const problem = (await response.json().catch(() => null)) as { code?: string } | null;
          if (problem?.code === "problem.auth.password_change_required") {
            setChanging({ username: values.username, required: true });
            return;
          }
        }
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
  if (changing) {
    return <LDAPPasswordChangeForm username={changing.username} required={changing.required} onDone={() => setChanging(null)} />;
  }
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
        {passwordChange && (
          <Button type="button" variant="ghost" className="w-full" onClick={() => setChanging({ required: false })}>
            {translateNow("auth.ldap.changePassword")}
          </Button>
        )}
      </fieldset>
    </form>
  );
}
