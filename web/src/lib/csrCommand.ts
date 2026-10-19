// A credential display name may contain shell syntax or may not be a DNS name.
// The copyable OpenSSL example uses one value in both filenames and the DNS SAN,
// so only a bounded ASCII DNS name can be inserted without quoting ambiguity.
const dnsLabel = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

export function safeCSRExampleName(value: string): string | null {
  const name = value.trim();
  if (name.length === 0 || name.length > 253) return null;
  if (!name.split(".").every((label) => dnsLabel.test(label))) return null;
  return name;
}
