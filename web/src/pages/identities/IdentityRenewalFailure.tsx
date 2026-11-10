import type { Identity } from "@/lib/api";
import { translateNow } from "@/i18n/I18nProvider";

/** A36: why the last host renewal did not complete, in plain words read from the
 * control plane's own records. The detail's lifecycle actions carry the one
 * Retry renewal; this names what it retries. */
export function IdentityRenewalFailure({ identity }: { identity: Identity }) {
  const cause = identity.status === "renewal_failed" ? identity.renewal_failure?.cause : undefined;
  if (!cause) return null;
  return (
    <p role="status" className="mt-2 rounded-md bg-muted px-3 py-2 text-xs font-medium text-foreground">
      {translateNow("identities.lifecycle.renewalFailedCause", { cause })}
    </p>
  );
}
