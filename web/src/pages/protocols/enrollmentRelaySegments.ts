import type { Agent } from "@/lib/api";

interface EnrollmentRelaySegment {
  name: string;
  publicURL: string;
  relays: Agent[];
}

export function enrollmentRelaySegments(agents: Agent[]): EnrollmentRelaySegment[] {
  const grouped = new Map<string, EnrollmentRelaySegment>();
  for (const agent of agents) {
    const proxy = agent.enrollment_proxy;
    if (agent.status === "offboarded" || !agent.roles.includes("network") || !proxy?.segment || !proxy.public_url) continue;
    // Two processes are redundant only when a stock client can use the same
    // authority through either one. A shared segment label with different
    // public URLs is two one-relay topologies, not one healthy two-relay pair.
    const key = JSON.stringify([proxy.segment, proxy.public_url]);
    const group = grouped.get(key) ?? { name: proxy.segment, publicURL: proxy.public_url, relays: [] };
    group.relays.push(agent);
    grouped.set(key, group);
  }
  return [...grouped.values()]
    .map((group) => ({ ...group, relays: group.relays.sort((left, right) => left.name.localeCompare(right.name)) }))
    .sort((left, right) => left.name.localeCompare(right.name) || left.publicURL.localeCompare(right.publicURL));
}
