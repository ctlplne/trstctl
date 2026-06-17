import "@testing-library/jest-dom/vitest";
import * as axeMatchers from "vitest-axe/matchers";
import { expect } from "vitest";

expect.extend(axeMatchers);

function memoryStorage(): Storage {
  const data = new Map<string, string>();
  return {
    get length() {
      return data.size;
    },
    clear: () => data.clear(),
    getItem: (key: string) => data.get(key) ?? null,
    key: (index: number) => Array.from(data.keys())[index] ?? null,
    removeItem: (key: string) => {
      data.delete(key);
    },
    setItem: (key: string, value: string) => {
      data.set(key, String(value));
    },
  };
}

function ensureStorage(name: "localStorage" | "sessionStorage") {
  // Always install the deterministic test store. Newer Node versions expose their
  // own experimental storage globals, which can warn or disappear depending on
  // runtime flags; the UI tests need browser storage semantics, not Node's process
  // storage feature.
  const store = memoryStorage();
  Object.defineProperty(window, name, { configurable: true, value: store });
  Object.defineProperty(globalThis, name, { configurable: true, value: store });
}

ensureStorage("localStorage");
ensureStorage("sessionStorage");

Object.defineProperty(HTMLCanvasElement.prototype, "getContext", {
  configurable: true,
  value: () => ({
    measureText: (text: string) => ({ width: text.length * 8 }),
  }),
});

// jsdom does not implement matchMedia; the theme provider needs it.
Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  }),
});
