import { Moon, Sun } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useTheme } from "@/components/ThemeProvider";
import { translateNow } from "@/i18n/I18nProvider";

/** ThemeToggle flips between exactly two modes — light and dark — based on the
 * currently-resolved appearance. (The OS default only applies on first load,
 * before the user has chosen; once they toggle, the choice is concrete.) */
export function ThemeToggle() {
  const { resolved, setTheme } = useTheme();
  const next = resolved === "dark" ? "light" : "dark";
  const Icon = resolved === "dark" ? Moon : Sun;
  const current = resolved === "dark" ? "Dark" : "Light";
  const nextLabel = next === "dark" ? "Dark" : "Light";
  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={() => setTheme(next)}
      aria-label={translateNow("source.theme.value1.switch.to.value2.b9ad93c6e2", { value1: current, value2: nextLabel })}
      title={translateNow("source.theme.value1.4049fcb6af", { value1: current })}
    >
      <Icon aria-hidden="true" className="h-4 w-4" />
    </Button>
  );
}
