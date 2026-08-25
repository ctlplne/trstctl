export function validateCatalog(value: unknown): Record<string, unknown>;
export function loadCanonicalCatalog(): Record<string, unknown>;
export function generateFromCatalog(value: unknown): string;
export function generate(): string;
export function readGenerated(): string;
export function computeMaturity(stages: Record<string, { status: string }>): string;

export const CATALOG: string;
export const MATURITIES: readonly string[];
export const OUT: string;
export const STAGE_NAMES: readonly string[];
export const STAGE_STATUSES: readonly string[];
export const TOOLS: readonly string[];
export const WEB: string;
