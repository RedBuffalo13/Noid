import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { uiStore } from "./ui_store.svelte";

describe("ui_store", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("subPage defaults to 'chats'", () => {
    expect(uiStore.subPage).toBe("chats");
  });

  it("subPage can be set", () => {
    uiStore.subPage = "settings";
    expect(uiStore.subPage).toBe("settings");
    // reset
    uiStore.subPage = "chats";
  });

  it("status defaults to empty string", () => {
    expect(uiStore.status).toBe("");
  });

  it("showToast sets status and clears after 3s", () => {
    uiStore.showToast("Test message");
    expect(uiStore.status).toBe("Test message");
    vi.advanceTimersByTime(3000);
    expect(uiStore.status).toBe("");
  });
});
