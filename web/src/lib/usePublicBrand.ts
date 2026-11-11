import { useEffect, useState } from "react";
import { api } from "./api";
import type { Brand } from "./api-types.gen";

// MSP-1: the console shows a Provider customer's brand (its product name, logo,
// sign-in message and design-token colors) where the control plane resolves
// one for this host, beside "Powered by trstctl". The brand is read once per
// page load; a failed read leaves the built-in brand.

export const defaultBrand: Brand = { product_name: "trstctl", custom: false };

let pending: Promise<Brand> | null = null;

function loadBrand(): Promise<Brand> {
  if (!pending) {
    try {
      pending = Promise.resolve(api.getPublicBrand()).then(
        (brand) => (brand && typeof brand.product_name === "string" ? brand : defaultBrand),
        () => defaultBrand,
      );
    } catch {
      pending = Promise.resolve(defaultBrand);
    }
  }
  return pending;
}

/** resetPublicBrand forgets the loaded brand (tests). */
export function resetPublicBrand(): void {
  pending = null;
}

const tokenName = /^--[a-z][a-z0-9-]{0,63}$/;
const unsafeValue = /url\(|expression\(|[;{}<>\\]/i;

/** brandTokenOverrides keeps the overrides the console applies: design-token
 * custom properties only, with plain values. */
export function brandTokenOverrides(brand: Brand): [string, string][] {
  if (!brand.custom || !brand.token_overrides) return [];
  const out: [string, string][] = [];
  for (const [name, raw] of Object.entries(brand.token_overrides)) {
    if (typeof raw !== "string" || !tokenName.test(name) || raw.length > 200 || unsafeValue.test(raw)) continue;
    out.push([name, raw]);
  }
  return out;
}

export function usePublicBrand(): Brand {
  const [brand, setBrand] = useState<Brand>(defaultBrand);
  useEffect(() => {
    let live = true;
    void loadBrand().then((loaded) => {
      if (live) setBrand(loaded);
    });
    return () => {
      live = false;
    };
  }, []);
  useEffect(() => {
    const overrides = brandTokenOverrides(brand);
    const root = document.documentElement;
    for (const [name, value] of overrides) root.style.setProperty(name, value);
    return () => {
      for (const [name] of overrides) root.style.removeProperty(name);
    };
  }, [brand]);
  return brand;
}
