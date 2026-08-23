import { useId } from "react";
import { Button } from "@/components/ui/button";

export type ProgressiveTask = {
  id: string;
  title: string;
  description: string;
  actionLabel: string;
};

export function ProgressiveTaskList({
  heading,
  description,
  tasks,
  activeTask,
  closeLabel,
  onTaskChange,
}: {
  heading: string;
  description: string;
  tasks: readonly ProgressiveTask[];
  activeTask: string | null;
  closeLabel: string;
  onTaskChange: (task: string | null) => void;
}) {
  const headingId = useId();

  return (
    <section data-testid="progressive-task-list" className="grid gap-3 border-y border-border py-4" aria-labelledby={headingId}>
      <div>
        <h2 id={headingId} className="text-title font-semibold">
          {heading}
        </h2>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{description}</p>
      </div>
      <div className="divide-y divide-border border-y border-border">
        {tasks.map((task) => {
          const open = activeTask === task.id;
          return (
            <div key={task.id} className="grid gap-3 py-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center">
              <div className="min-w-0">
                <h3 className="font-medium text-foreground">{task.title}</h3>
                <p className="mt-0.5 max-w-3xl text-sm text-muted-foreground">{task.description}</p>
              </div>
              <Button
                type="button"
                variant="outline"
                aria-controls={`task-panel-${task.id}`}
                aria-expanded={open}
                onClick={() => onTaskChange(open ? null : task.id)}
              >
                {open ? closeLabel : task.actionLabel}
              </Button>
            </div>
          );
        })}
      </div>
    </section>
  );
}
