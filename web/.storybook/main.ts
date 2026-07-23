import path from "node:path";
import { fileURLToPath } from "node:url";
import type { StorybookConfig } from "@storybook/react-vite";

const configDir = path.dirname(fileURLToPath(import.meta.url));

/** S-C8: the component workbench. Stories live beside their components
 * (src/[**]/*.stories.tsx) and render against the real tokens — preview.ts
 * imports src/index.css, so what Storybook shows is what ships. addon-a11y
 * runs axe on every story. `npm run storybook` to develop,
 * `npm run storybook:build` for the static workbench. */
const config: StorybookConfig = {
  stories: ["../src/**/*.stories.tsx"],
  addons: ["@storybook/addon-a11y"],
  framework: { name: "@storybook/react-vite", options: {} },
  viteFinal: (viteConfig) => {
    viteConfig.resolve = viteConfig.resolve ?? {};
    viteConfig.resolve.alias = {
      ...(viteConfig.resolve.alias ?? {}),
      "@": path.resolve(configDir, "../src"),
    };
    return viteConfig;
  },
};

export default config;
