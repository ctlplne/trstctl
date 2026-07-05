/** Manual journey-step completion marks: which command/config steps the
 * operator has ticked off by hand (steps with a served-data detector complete
 * themselves and are never stored). Pure UI metadata — no identifiers, no
 * auth material — kept in its own module so the security-sink scan can allow
 * it explicitly, like the theme and nav-collapse preferences. */

const JOURNEY_PROGRESS_KEY = "trstctl-journey-progress";

function markId(journeyId: string, stepId: string): string {
  return `${journeyId}:${stepId}`;
}

export function readJourneyMarks(): Set<string> {
  try {
    const raw = localStorage.getItem(JOURNEY_PROGRESS_KEY);
    if (!raw) return new Set();
    const parsed = JSON.parse(raw) as unknown;
    return new Set(Array.isArray(parsed) ? parsed.filter((value): value is string => typeof value === "string") : []);
  } catch {
    return new Set();
  }
}

export function persistJourneyMarks(marks: Set<string>): void {
  try {
    localStorage.setItem(JOURNEY_PROGRESS_KEY, JSON.stringify(Array.from(marks)));
  } catch {
    // Storage unavailable: manual marks are a convenience only.
  }
}

export function hasJourneyMark(marks: Set<string>, journeyId: string, stepId: string): boolean {
  return marks.has(markId(journeyId, stepId));
}

// Return type left inferred: back-to-back generics in one signature span trip
// the i18n extractor's JSX-text heuristic into logging junk "copy".
export function toggleJourneyMark(marks: Set<string>, journeyId: string, stepId: string) {
  const next = new Set(marks);
  const id = markId(journeyId, stepId);
  if (next.has(id)) {
    next.delete(id);
  } else {
    next.add(id);
  }
  persistJourneyMarks(next);
  return next;
}
