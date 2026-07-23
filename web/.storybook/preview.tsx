import { useEffect } from "react";
import { MemoryRouter } from "react-router-dom";
import type { Decorator, Preview } from "@storybook/react-vite";
import { IntlProvider } from "../src/i18n/I18nProvider";
import "../src/index.css";

/** Every story renders inside the app's providers against the real tokens.
 * The theme toolbar flips the `dark` class on <html> — dark first, it is the
 * flagship theme. */
const withProviders: Decorator = (Story, context) => {
  const theme = (context.globals.theme as string) ?? "dark";
  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark");
  }, [theme]);
  return (
    <IntlProvider initialLocale="en-US" initialTimeZone="UTC">
      <MemoryRouter>
        <div className="bg-background p-6 text-foreground">
          <Story />
        </div>
      </MemoryRouter>
    </IntlProvider>
  );
};

const preview: Preview = {
  decorators: [withProviders],
  globalTypes: {
    theme: {
      description: "Color theme",
      toolbar: { title: "Theme", items: ["dark", "light"], dynamicTitle: true },
    },
  },
  initialGlobals: { theme: "dark" },
  parameters: {
    layout: "fullscreen",
    backgrounds: { disable: true },
  },
};

export default preview;
