import { describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { IntlProvider } from "@/i18n/I18nProvider";
import { IdentityRenewalFailure } from "@/pages/identities/IdentityRenewalFailure";
import type { Identity } from "@/lib/api";

const identity = (status: string, cause?: string): Identity =>
  ({
    id: "ident-1",
    kind: "x509_certificate",
    name: "svc.example.test",
    status,
    owner_id: "owner-1",
    renewal_failure: cause ? { cause, job_id: 6, attempt: 2 } : undefined,
  }) as unknown as Identity;

function show(value: Identity) {
  return render(
    <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
      <IdentityRenewalFailure identity={value} />
    </IntlProvider>,
  );
}

// A36: a renewal_failed identity says why in plain words; nothing else does.
describe("renewal failure cause in identity detail", () => {
  it("states the cause of a failed renewal", () => {
    cleanup();
    show(identity("renewal_failed", "The certificate authority could not validate the domain: its order or DNS-01 challenge failed."));
    expect(screen.getByRole("status").textContent).toBe(
      "The last renewal failed. The certificate authority could not validate the domain: its order or DNS-01 challenge failed.",
    );
  });

  it("says nothing for an identity that is not renewal_failed or has no recorded cause", () => {
    cleanup();
    show(identity("deployed", "stale cause"));
    expect(screen.queryByRole("status")).toBeNull();
    cleanup();
    show(identity("renewal_failed"));
    expect(screen.queryByRole("status")).toBeNull();
  });
});
