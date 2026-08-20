import { useId, type Ref } from "react";
import type { Identity } from "@/lib/api";

/** IdentityPicker — DESIGN rule 13 made concrete for identity fields (DA-10):
 * known entities render as datalist autocomplete fed from loaded data, never a
 * bare UUID input. The datalist is a suggestion surface over a plain input, so
 * free typing (pasted ids, automation, existing fixtures) keeps working and
 * the submitted value stays the identity id.
 *
 * Reused beyond Incidents: the closeout train's Secrets grant flow (C-S1) and
 * the future approvals pending-list card consume the same component. */
export function IdentityPicker({
  value,
  onChange,
  identities,
  id,
  placeholder,
  filterKinds,
  className,
  inputRef,
}: {
  value: string;
  onChange: (next: string) => void;
  identities: Identity[];
  id?: string;
  placeholder?: string;
  /** Restrict suggestions to these identity kinds (submission stays free-form). */
  filterKinds?: string[];
  className?: string;
  inputRef?: Ref<HTMLInputElement>;
}) {
  const listId = useId();
  const options = filterKinds?.length ? identities.filter((identity) => filterKinds.includes(identity.kind)) : identities;
  return (
    <>
      <input
        ref={inputRef}
        id={id}
        className={className ?? "ui-input font-mono"}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        list={listId}
        placeholder={placeholder}
      />
      {/* Option display text rides the `label` attribute, not a text child:
          the datalist renders inside the field's <label>, and option text
          children would pollute the accessible label name. */}
      <datalist id={listId}>
        {options.map((identity) => (
          <option key={identity.id} value={identity.id} label={`${identity.name} (${identity.kind}, ${identity.status})`} />
        ))}
      </datalist>
    </>
  );
}
