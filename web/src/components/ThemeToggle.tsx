import { Moon, Sun } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useTheme } from "@/components/ThemeProvider";

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
      aria-label={`Theme: ${current}. Switch to ${nextLabel}.`}
      title={`Theme: ${current}`}
    >
      <Icon aria-hidden="true" className="h-4 w-4" />
    </Button>
  );
}
