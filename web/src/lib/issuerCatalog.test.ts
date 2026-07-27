import { describe, expect, it } from "vitest";
import { defaultIssuerConfigValues, isSensitiveIssuerField, issuerTypes, splitPEMChain } from "@/lib/issuerCatalog";

describe("issuer catalog contract", () => {
  it("keeps every issuer and field uniquely addressable with rendered operator copy", () => {
    expect(new Set(issuerTypes.map((type) => type.id)).size).toBe(issuerTypes.length);

    for (const type of issuerTypes) {
      expect(type.name.trim(), `${type.id} name`).not.toBe("");
      expect(type.description.trim(), `${type.id} description`).not.toBe("");
      expect(new Set(type.configFields.map((field) => field.key)).size, `${type.id} duplicate field`).toBe(type.configFields.length);
      for (const field of type.configFields) {
        expect(field.label.trim(), `${type.id}.${field.key} label`).not.toBe("");
        if (field.type === "select") {
          expect(field.options?.length, `${type.id}.${field.key} select options`).toBeGreaterThan(0);
        }
      }
    }
  });

  it("derives only declared defaults and classifies secret-shaped fields fail-closed", () => {
    for (const type of issuerTypes) {
      const expected = Object.fromEntries(
        type.configFields.filter((field) => field.defaultValue !== undefined).map((field) => [field.key, field.defaultValue]),
      );
      expect(defaultIssuerConfigValues(type), type.id).toEqual(expected);
    }

    expect(isSensitiveIssuerField({ key: "username", sensitive: true })).toBe(true);
    for (const key of ["PASSWORD", "api_secret", "accessToken", "private_material", "hmac_value", "client_key"]) {
      expect(isSensitiveIssuerField({ key }), key).toBe(true);
    }
    expect(isSensitiveIssuerField({ key: "region" })).toBe(false);
  });

  it("splits a certificate chain without inventing empty certificates", () => {
    const leaf = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----";
    const root = "-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----";

    expect(splitPEMChain(`\n${leaf}\n${root}\n`)).toEqual([leaf, root]);
    expect(splitPEMChain(" \n ")).toEqual([]);
  });
});
