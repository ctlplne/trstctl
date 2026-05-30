import "vitest";

// Augment vitest's expect with the axe accessibility matcher (vitest-axe).
declare module "vitest" {
  interface Assertion<T = unknown> {
    toHaveNoViolations(): T;
  }
  interface AsymmetricMatchersContaining {
    toHaveNoViolations(): void;
  }
}
