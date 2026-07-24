import { useId, type ReactNode } from "react";
import { cn } from "@/lib/utils";

export type FieldControlProps = {
  id: string;
  "aria-describedby"?: string;
  "aria-invalid"?: true;
  "aria-required"?: true;
};

/** Field — label + control + description + error as ONE accessible unit
 * (DESIGN rule 14). The render-prop hands the control its id and aria wiring,
 * so htmlFor/aria-describedby/aria-invalid can never drift apart from the
 * markup around them:
 *
 *   <Field label={t("…")} error={errors.name?.message} required>
 *     {(control) => <Input {...control} {...register("name")} />}
 *   </Field>
 *
 * The description sits under the control and is announced via
 * aria-describedby; the error is announced the same way and flips the
 * control's aria-invalid, which .ui-input renders as a destructive border.
 * Field itself contains no copy — label, description, and error arrive
 * translated from the caller. */
export function Field({
  label,
  description,
  error,
  required,
  className,
  children,
}: {
  label: ReactNode;
  description?: ReactNode;
  error?: ReactNode;
  required?: boolean;
  className?: string;
  children: (control: FieldControlProps) => ReactNode;
}) {
  const id = useId();
  const descriptionId = description ? `${id}-description` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  const describedBy = [descriptionId, errorId].filter(Boolean).join(" ") || undefined;
  return (
    <div className={cn("grid gap-1", className)}>
      <label htmlFor={id} className="text-body font-medium">
        {label}
      </label>
      {children({
        id,
        "aria-describedby": describedBy,
        "aria-invalid": error ? true : undefined,
        "aria-required": required || undefined,
      })}
      {description && (
        <p id={descriptionId} className="text-caption text-muted-foreground">
          {description}
        </p>
      )}
      {error && (
        <p id={errorId} className="text-caption font-medium text-risk-critical">
          {error}
        </p>
      )}
    </div>
  );
}
