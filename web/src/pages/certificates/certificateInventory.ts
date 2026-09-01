import type { Certificate, Owner } from "@/lib/api";
import { translateNow } from "@/i18n/I18nProvider";

function certificateRecord(certificate: Certificate): Record<string, unknown> {
  return certificate as unknown as Record<string, unknown>;
}

function certificateAttributes(certificate: Certificate): Record<string, unknown> {
  const value = certificateRecord(certificate).attributes;
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function firstString(certificate: Certificate, keys: string[]): string {
  const record = certificateRecord(certificate);
  const attributes = certificateAttributes(certificate);
  for (const key of keys) {
    const value = record[key] ?? attributes[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return "";
}

export function certificateProfile(certificate: Certificate): string {
  return firstString(certificate, ["profile_name", "profile", "certificate_profile_name", "certificate_profile_id"]);
}

export function certificateEnvironment(certificate: Certificate): string {
  const explicit = firstString(certificate, ["environment", "env"]);
  if (explicit) return explicit;
  const location = certificate.deployment_location?.toLowerCase() ?? "";
  for (const candidate of ["production", "prod", "staging", "stage", "development", "dev"]) {
    if (new RegExp(`(^|[^a-z])${candidate}([^a-z]|$)`).test(location)) return candidate;
  }
  return "";
}

export function certificateTeamID(certificate: Certificate, ownerByID: Map<string, Owner>): string {
  const explicit = firstString(certificate, ["team_id"]);
  if (explicit) return explicit;
  if (certificate.owner_id && ownerByID.get(certificate.owner_id)?.kind === "team") return certificate.owner_id;
  return "";
}

export function certificateTeamLabel(certificate: Certificate, ownerByID: Map<string, Owner>): string {
  const explicitName = firstString(certificate, ["team_name", "team"]);
  if (explicitName) return explicitName;
  const teamID = certificateTeamID(certificate, ownerByID);
  if (!teamID) return "";
  return ownerByID.get(teamID)?.name || teamID;
}

export function ownerIsReachable(owner: Owner): boolean {
  return Boolean(owner.email?.trim() || owner.escalation_chain.some((entry) => entry.trim()));
}

export function effectiveOwnershipLabel(owner: Owner): string {
  if (!owner.ownership_complete) return translateNow("certificateCockpit.detail.incomplete");
  if (!owner.ownership_current) return translateNow("certificateCockpit.detail.notCurrent");
  if (!owner.ownership_attested) return translateNow("certificateCockpit.detail.notAttested");
  return translateNow("certificateCockpit.detail.current");
}

export function teamFacetOptions(
  certificates: Certificate[],
  ownerByID: Map<string, Owner>,
  owners: Owner[],
  selected: string,
): Array<{ value: string; label: string }> {
  const options = new Map<string, string>();
  for (const owner of owners) {
    if (owner.kind === "team") options.set(owner.id, owner.name || owner.id);
  }
  for (const certificate of certificates) {
    const teamID = certificateTeamID(certificate, ownerByID);
    if (teamID) options.set(teamID, certificateTeamLabel(certificate, ownerByID) || teamID);
  }
  if (selected !== "all" && !options.has(selected)) options.set(selected, selected);
  return Array.from(options, ([value, label]) => ({ value, label })).sort((left, right) => left.label.localeCompare(right.label));
}
