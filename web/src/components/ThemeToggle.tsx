import { Monitor, Moon, Sun } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useTheme, type Theme } from "@/components/ThemeProvider";

const order: Theme[] = ["light", "dark", "system"];
const icon = { light: Sun, dark: Moon, system: Monitor } as const;
const label = { light: "Light", dark: "Dark", system: "System" } as const;

/** ThemeToggle cycles light -> dark -> system; the current mode is announced for
 * screen readers. */
export function ThemeToggle() {
  const { theme, setTheme } = useTheme();
  const Icon = icon[theme];
  const next = order[(order.indexOf(theme) + 1) % order.length];
  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={() => setTheme(next)}
      aria-label={`Theme: ${label[theme]}. Switch to ${label[next]}.`}
      title={`Theme: ${label[theme]}`}
    >
      <Icon aria-hidden="true" className="h-4 w-4" />
    </Button>
  );
}
