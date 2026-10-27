import { describe, it, expect, vi, beforeEach } from "vitest";
import { t } from "$lib/i18n/index.svelte";

vi.mock("$lib/services", () => ({
  login: vi.fn(),
  setupPins: vi.fn(),
  isFirstRun: vi.fn(),
}));

vi.mock("./profile_store.svelte", () => ({
  profileStore: { loadProfile: vi.fn() },
}));

vi.mock("./contact_store.svelte", () => ({
  contactStore: { loadContacts: vi.fn() },
}));

vi.mock("./ui_store.svelte", () => ({
  uiStore: { showToast: vi.fn(), subPage: "chats", resetNav: vi.fn() },
}));

vi.mock("./username_store.svelte", () => ({
  usernameStore: { loadUsername: vi.fn() },
}));

import { authStore } from "./auth_store.svelte";
import { login, setupPins, isFirstRun } from "$lib/services";
import { profileStore } from "./profile_store.svelte";
import { contactStore } from "./contact_store.svelte";
import { uiStore } from "./ui_store.svelte";
import { usernameStore } from "./username_store.svelte";

describe("auth_store", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    authStore.screen = "checking";
    authStore.pin = "";
    authStore.truePin = "";
    authStore.confirmTruePin = "";
    authStore.killPin = "";
    authStore.confirmKillPin = "";
  });

  describe("checkFirstRun", () => {
    it("sets screen to 'setup' on first run", async () => {
      vi.mocked(isFirstRun).mockResolvedValue(true);
      await authStore.checkFirstRun();
      expect(authStore.screen).toBe("setup");
    });

    it("sets screen to 'pin-entry' on subsequent runs", async () => {
      vi.mocked(isFirstRun).mockResolvedValue(false);
      await authStore.checkFirstRun();
      expect(authStore.screen).toBe("pin-entry");
    });

    it("sets screen to 'pin-entry' on error", async () => {
      vi.mocked(isFirstRun).mockRejectedValue(new Error("fail"));
      await authStore.checkFirstRun();
      expect(authStore.screen).toBe("pin-entry");
    });
  });

  describe("handleAuth", () => {
    it("does nothing when pin < 8 chars", async () => {
      authStore.pin = "1234567";
      await authStore.handleAuth();
      expect(login).not.toHaveBeenCalled();
    });

    it("loads profile/contacts/username and sets screen to main on success", async () => {
      vi.mocked(login).mockResolvedValue({ success: true, message: "ok", kind: "ok" });
      authStore.pin = "12345678";
      await authStore.handleAuth();
      expect(login).toHaveBeenCalledWith("12345678");
      expect(profileStore.loadProfile).toHaveBeenCalled();
      expect(contactStore.loadContacts).toHaveBeenCalled();
      expect(usernameStore.loadUsername).toHaveBeenCalled();
      expect(authStore.screen).toBe("main");
    });

    it("shows toast and clears pin on WIPED message", async () => {
      vi.mocked(login).mockResolvedValue({ success: true, message: "WIPED", kind: "wiped" });
      authStore.pin = "12345678";
      await authStore.handleAuth();
      expect(uiStore.showToast).toHaveBeenCalledWith(t("auth.toast.wiped"));
      expect(authStore.pin).toBe("");
      // FE-13: after a wipe the vault is gone — the next step is re-setup.
      expect(authStore.screen).toBe("setup");
    });

    it("surfaces the backend message on !success", async () => {
      vi.mocked(login).mockResolvedValue({ success: false, message: "fail", kind: "failed" });
      authStore.pin = "12345678";
      await authStore.handleAuth();
      expect(uiStore.showToast).toHaveBeenCalledWith("fail");
      expect(authStore.pin).toBe("");
    });

    it("shows Authentication Error on exception", async () => {
      vi.mocked(login).mockRejectedValue(new Error("fail"));
      authStore.pin = "12345678";
      await authStore.handleAuth();
      expect(uiStore.showToast).toHaveBeenCalledWith(t("auth.toast.error"));
    });
  });

  describe("handleSetup", () => {
    it("shows toast when truePins don't match", async () => {
      authStore.truePin = "12345678";
      authStore.confirmTruePin = "87654321";
      await authStore.handleSetup();
      expect(uiStore.showToast).toHaveBeenCalledWith(t("auth.toast.mainMismatch"));
      expect(setupPins).not.toHaveBeenCalled();
    });

    it("shows toast when killPins don't match", async () => {
      authStore.truePin = "12345678";
      authStore.confirmTruePin = "12345678";
      authStore.killPin = "11111111";
      authStore.confirmKillPin = "22222222";
      await authStore.handleSetup();
      expect(uiStore.showToast).toHaveBeenCalledWith(t("auth.toast.killMismatch"));
    });

    it("shows toast when truePin < 8 chars", async () => {
      authStore.truePin = "1234567";
      authStore.confirmTruePin = "1234567";
      authStore.killPin = "11111111";
      authStore.confirmKillPin = "11111111";
      await authStore.handleSetup();
      expect(uiStore.showToast).toHaveBeenCalledWith(t("auth.toast.mainShort"));
    });

    it("shows toast when killPin < 8 chars", async () => {
      authStore.truePin = "12345678";
      authStore.confirmTruePin = "12345678";
      authStore.killPin = "1111111";
      authStore.confirmKillPin = "1111111";
      await authStore.handleSetup();
      expect(uiStore.showToast).toHaveBeenCalledWith(t("auth.toast.killShort"));
    });

    it("shows toast when truePin == killPin", async () => {
      authStore.truePin = "12345678";
      authStore.confirmTruePin = "12345678";
      authStore.killPin = "12345678";
      authStore.confirmKillPin = "12345678";
      await authStore.handleSetup();
      expect(uiStore.showToast).toHaveBeenCalledWith(t("auth.toast.samePins"));
    });

    it("sets screen to pin-entry on success and clears pins", async () => {
      vi.mocked(setupPins).mockResolvedValue({ success: true, message: "ok", kind: "ok" });
      authStore.truePin = "12345678";
      authStore.confirmTruePin = "12345678";
      authStore.killPin = "87654321";
      authStore.confirmKillPin = "87654321";
      await authStore.handleSetup();
      expect(setupPins).toHaveBeenCalledWith("12345678", "87654321");
      expect(authStore.screen).toBe("pin-entry");
      expect(authStore.truePin).toBe("");
      expect(authStore.killPin).toBe("");
    });

    it("shows error toast on !success", async () => {
      vi.mocked(setupPins).mockResolvedValue({ success: false, message: "db error", kind: "failed" });
      authStore.truePin = "12345678";
      authStore.confirmTruePin = "12345678";
      authStore.killPin = "87654321";
      authStore.confirmKillPin = "87654321";
      await authStore.handleSetup();
      expect(uiStore.showToast).toHaveBeenCalledWith(t("auth.toast.setupError", { e: "db error" }));
    });
  });

  describe("resetSetup", () => {
    it("clears all pin fields", () => {
      authStore.truePin = "12345678";
      authStore.confirmTruePin = "12345678";
      authStore.killPin = "87654321";
      authStore.confirmKillPin = "87654321";
      authStore.resetSetup();
      expect(authStore.truePin).toBe("");
      expect(authStore.confirmTruePin).toBe("");
      expect(authStore.killPin).toBe("");
      expect(authStore.confirmKillPin).toBe("");
    });
  });
});
