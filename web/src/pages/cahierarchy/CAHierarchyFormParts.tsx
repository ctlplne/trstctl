import type { ReactNode, RefObject } from "react";

export function LabeledSelect({
  children,
  id,
  label,
  onChange,
  value,
}: {
  children: ReactNode;
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className="grid gap-2">
      <label className="text-sm font-medium" htmlFor={id}>
        {label}
      </label>
      <select
        id={id}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="rounded-control border border-border bg-background px-3 py-2 outline-none transition-colors focus:border-focus focus:ring-2 focus:ring-focus/20"
      >
        {children}
      </select>
    </div>
  );
}

export function LabeledInput({
  id,
  label,
  onChange,
  placeholder,
  required,
  type = "text",
  value,
  inputRef,
}: {
  id: string;
  label: string;
  value: string;
  type?: "text" | "password" | "number";
  required?: boolean;
  placeholder?: string;
  onChange: (value: string) => void;
  inputRef?: RefObject<HTMLInputElement>;
}) {
  return (
    <div className="grid gap-2">
      <label className="text-sm font-medium" htmlFor={id}>
        {label}
      </label>
      <input
        ref={inputRef}
        id={id}
        type={type}
        required={required}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="h-10 rounded-control border border-border bg-background px-3 text-sm outline-none transition-colors placeholder:text-muted-foreground focus:border-focus focus:ring-2 focus:ring-focus/20"
      />
    </div>
  );
}

export function KeyValue({ label, mono = false, value }: { label: string; mono?: boolean; value: ReactNode }) {
  return (
    <div>
      <dt className="font-medium text-muted-foreground">{label}</dt>
      <dd className={mono ? "break-all font-mono text-xs" : "font-medium"}>{value}</dd>
    </div>
  );
}
