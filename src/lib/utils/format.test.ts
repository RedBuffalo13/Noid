import { describe, it, expect } from "vitest";
import { formatId, formatTimestamp } from "./format";

describe("formatId", () => {
  it("returns short IDs unchanged (<=20 chars)", () => {
    expect(formatId("shortid123")).toBe("shortid123");
    expect(formatId("12345678901234567890")).toBe("12345678901234567890");
  });

  it("truncates long IDs to first10...last5", () => {
    const longId = "1234567890abcdefghij12345";
    expect(formatId(longId)).toBe("1234567890...12345");
  });

  it("handles empty string", () => {
    expect(formatId("")).toBe("");
  });

  it("handles exactly 21 chars (truncates)", () => {
    const id = "123456789012345678901";
    expect(formatId(id)).toBe("1234567890...78901");
  });
});

describe("formatTimestamp", () => {
  it("returns 'Now' for < 1 minute ago", () => {
    const now = Date.now();
    expect(formatTimestamp(now)).toBe("Now");
    expect(formatTimestamp(now - 30000)).toBe("Now"); // 30s ago
  });

  it("returns 'Xm ago' for < 60 minutes", () => {
    const now = Date.now();
    expect(formatTimestamp(now - 60000)).toBe("1m ago");
    expect(formatTimestamp(now - 5 * 60000)).toBe("5m ago");
    expect(formatTimestamp(now - 59 * 60000)).toBe("59m ago");
  });

  it("returns 'Xh ago' for < 24 hours", () => {
    const now = Date.now();
    expect(formatTimestamp(now - 60 * 60000)).toBe("1h ago");
    expect(formatTimestamp(now - 5 * 3600000)).toBe("5h ago");
    expect(formatTimestamp(now - 23 * 3600000)).toBe("23h ago");
  });

  it("returns 'Xd ago' for >= 24 hours", () => {
    const now = Date.now();
    expect(formatTimestamp(now - 24 * 3600000)).toBe("1d ago");
    expect(formatTimestamp(now - 7 * 24 * 3600000)).toBe("7d ago");
  });
});
