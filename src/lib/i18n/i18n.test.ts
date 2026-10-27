import { describe, it, expect, beforeEach } from "vitest";
import { i18n, t } from "./index.svelte";
import { en } from "./en";
import { ru } from "./ru";

describe("i18n", () => {
  beforeEach(() => {
    localStorage.clear();
    i18n.setLocale("en");
  });

  it("defaults to English", () => {
    expect(i18n.locale).toBe("en");
    expect(t("nav.settings")).toBe("Settings");
  });

  it("switches to Russian and back", () => {
    i18n.setLocale("ru");
    expect(t("nav.settings")).toBe("Настройки");
    i18n.setLocale("en");
    expect(t("nav.settings")).toBe("Settings");
  });

  it("persists the locale to localStorage", () => {
    i18n.setLocale("ru");
    expect(localStorage.getItem("noid.locale")).toBe("ru");
  });

  it("interpolates {name} params", () => {
    expect(t("auth.login.locked", { s: 42 })).toBe("Too many failed attempts. Try again in 42s");
    i18n.setLocale("ru");
    expect(t("auth.login.locked", { s: 5 })).toContain("5");
  });

  it("ru dictionary covers every en key", () => {
    for (const key of Object.keys(en)) {
      expect(ru[key as keyof typeof ru], `missing ru key: ${key}`).toBeTruthy();
    }
  });
});
