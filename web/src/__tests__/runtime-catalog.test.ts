import { describe, expect, it } from "vitest";

import { defaultMessageValues, orderedMessageKeys } from "@/i18n/catalog.en-US.runtime.gen";
import { messages } from "@/i18n/messages";

describe("compressed production message catalog", () => {
  it("restores every typed key in order with its original English value", () => {
    const sourceKeys = Object.keys(messages);
    expect(orderedMessageKeys).toEqual(sourceKeys);
    expect(defaultMessageValues).toHaveLength(sourceKeys.length);
    for (let index = 0; index < sourceKeys.length; index++) {
      expect(defaultMessageValues[index]).toBe(messages[sourceKeys[index] as keyof typeof messages].defaultMessage);
    }
  });
});
