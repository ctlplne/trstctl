import { api } from "./api";

// Calling an api method that may not exist on the client.
//
// This exists because the same defect has now shipped four times: a panel calls
// api.someMethod() unconditionally, and anywhere the client is a partial object
// — a test fixture, a mock, a console served by an older build — the call
// throws during render and takes down the WHOLE PAGE rather than hiding one
// panel. A missing panel is a missing panel; a blank Platform page because DR
// posture was unavailable is an outage.
//
// The fallback is a value the caller chooses, so each panel decides what
// "absent" looks like for it. There is deliberately no default: an empty object
// would let a panel render zeros as though they were measurements, which is the
// other half of this same mistake.
export function optionalApiCall<T>(name: keyof typeof api, fallback: T): Promise<T> {
  const client = api as unknown as Record<string, unknown>;
  const fn = client[name as string];
  return typeof fn === "function" ? (fn as () => Promise<T>)() : Promise.resolve(fallback);
}
