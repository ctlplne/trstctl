// SPDX-License-Identifier: BUSL-1.1

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { IntlProvider } from "@/i18n/I18nProvider";
import { CodeSigningKeyCertificate } from "@/pages/codesigning/CodeSigningKeyCertificate";
import { ApiError, api } from "@/lib/api";

const chain = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
const attached = {
  key_id: "release-key",
  algorithm: "ECDSA-P256",
  public_key_der: "MFkw",
  chain_pem: chain,
  leaf_fingerprint: "ab".repeat(32),
  not_after: "2027-11-12T00:00:00Z",
  code_signing_eku: true,
  source: "attached" as const,
  attached_by: "release-admin",
  attached_at: "2026-11-12T12:00:00Z",
};

// P9-L1: the Code signing page reads a key's certificate chain and attaches
// or rotates it, without a restart.
describe("code-signing key certificate", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("shows a key with no chain, attaches one and shows where it came from", async () => {
    vi.spyOn(api, "codeSigningKeyCertificate").mockRejectedValue(new ApiError(404, JSON.stringify({ detail: "no certificate chain" })));
    const attach = vi.spyOn(api, "attachCodeSigningKeyCertificate").mockResolvedValue(attached);
    const user = userEvent.setup();
    const { container } = render(
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <CodeSigningKeyCertificate />
      </IntlProvider>,
    );
    expect(screen.getByRole("button", { name: "Attach chain" })).toBeDisabled();
    await user.type(screen.getByLabelText(/Key ID/), "release-key");
    await user.click(screen.getByRole("button", { name: "Show certificate" }));
    expect(await screen.findByText("No certificate chain is attached or configured for this key yet.")).toBeInTheDocument();
    await user.click(screen.getByLabelText(/Certificate chain/));
    await user.paste(chain);
    await user.click(screen.getByRole("button", { name: "Attach chain" }));
    await waitFor(() => expect(attach).toHaveBeenCalledWith("release-key", chain, expect.any(String)));
    expect(await screen.findByRole("status")).toHaveTextContent("Chain attached to release-key; signing tools get it now.");
    expect(screen.getByText("Attached here")).toBeInTheDocument();
    expect(screen.getByText("ab".repeat(32))).toBeInTheDocument();
    expect(screen.getByText("release-admin")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("names the server's refusal of a chain that does not fit the key", async () => {
    vi.spyOn(api, "attachCodeSigningKeyCertificate").mockRejectedValue(
      new ApiError(422, JSON.stringify({ detail: "codesign: the certificate chain does not fit this key: the leaf certificate does not name this key" })),
    );
    const user = userEvent.setup();
    render(
      <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
        <CodeSigningKeyCertificate />
      </IntlProvider>,
    );
    await user.type(screen.getByLabelText(/Key ID/), "release-key");
    await user.click(screen.getByLabelText(/Certificate chain/));
    await user.paste(chain);
    await user.click(screen.getByRole("button", { name: "Attach chain" }));
    expect(await screen.findByText(/does not name this key/)).toBeInTheDocument();
  });
});
