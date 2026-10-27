import { describe, it, expect, vi, beforeEach } from "vitest";
import { t } from "$lib/i18n/index.svelte";

const { invokeMock, openMock, readFileMock, writeTextMock } = vi.hoisted(() => ({
  invokeMock: vi.fn(),
  openMock: vi.fn(),
  readFileMock: vi.fn(),
  writeTextMock: vi.fn(),
}));

vi.mock("@tauri-apps/api/core", () => ({ invoke: invokeMock }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: openMock }));
vi.mock("@tauri-apps/plugin-fs", () => ({ readFile: readFileMock }));
vi.mock("@tauri-apps/plugin-clipboard-manager", () => ({ writeText: writeTextMock }));

vi.mock("./ui_store.svelte", () => ({
  uiStore: { showToast: vi.fn(), subPage: "chats", resetNav: vi.fn() },
}));

import { profileStore } from "./profile_store.svelte";
import { uiStore } from "./ui_store.svelte";

describe("profile_store", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    openMock.mockReset();
    readFileMock.mockReset();
    writeTextMock.mockReset();
    profileStore.nickname = "NoidUser";
    profileStore.avatar = null;
  });

  describe("loadProfile", () => {
    it("loads nickname and avatar from invoke", async () => {
      invokeMock.mockResolvedValue(["Alice", "avatar-data"]);
      await profileStore.loadProfile();
      expect(invokeMock).toHaveBeenCalledWith("get_profile");
      expect(profileStore.nickname).toBe("Alice");
      expect(profileStore.avatar).toBe("avatar-data");
    });

    it("keeps default nickname when null returned", async () => {
      invokeMock.mockResolvedValue([null, null]);
      await profileStore.loadProfile();
      expect(profileStore.nickname).toBe("NoidUser");
    });

    it("logs error on failure", async () => {
      invokeMock.mockRejectedValue(new Error("fail"));
      const spy = vi.spyOn(console, "error").mockImplementation(() => {});
      await profileStore.loadProfile();
      spy.mockRestore();
    });
  });

  describe("saveProfile", () => {
    it("calls invoke('update_profile') and shows toast", async () => {
      invokeMock.mockResolvedValue(undefined);
      profileStore.nickname = "Bob";
      profileStore.avatar = "avatar";
      await profileStore.saveProfile();
      expect(invokeMock).toHaveBeenCalledWith("update_profile", {
        nickname: "Bob",
        avatar: "avatar",
      });
      expect(uiStore.showToast).toHaveBeenCalledWith(t("profile.toast.updated"));
    });

    it("shows error toast on failure", async () => {
      invokeMock.mockRejectedValue(new Error("fail"));
      await profileStore.saveProfile();
      expect(uiStore.showToast).toHaveBeenCalledWith(t("profile.toast.saveFailed", { e: "Error: fail" }));
    });
  });

  describe("pickAvatar", () => {
    it("does nothing when dialog returns null", async () => {
      openMock.mockResolvedValue(null);
      await profileStore.pickAvatar();
      expect(profileStore.avatar).toBeNull();
    });

    it("shows error toast on failure", async () => {
      openMock.mockRejectedValue(new Error("fail"));
      await profileStore.pickAvatar();
      expect(uiStore.showToast).toHaveBeenCalledWith(t("profile.toast.imageInvalid"));
    });
  });

  describe("copyId", () => {
    it("uses writeText and shows toast on success", async () => {
      writeTextMock.mockResolvedValue(undefined);
      await profileStore.copyId("peer123");
      expect(writeTextMock).toHaveBeenCalledWith("peer123");
      expect(uiStore.showToast).toHaveBeenCalledWith(t("profile.toast.idCopied"));
    });

    it("falls back to navigator.clipboard on writeText error", async () => {
      writeTextMock.mockRejectedValue(new Error("fail"));
      const navClipboard = { writeText: vi.fn().mockResolvedValue(undefined) };
      Object.defineProperty(navigator, "clipboard", {
        value: navClipboard,
        configurable: true,
      });
      await profileStore.copyId("peer123");
      expect(navClipboard.writeText).toHaveBeenCalledWith("peer123");
      expect(uiStore.showToast).toHaveBeenCalledWith(t("profile.toast.idCopied"));
    });

    it("shows Copy failed when both methods fail", async () => {
      writeTextMock.mockRejectedValue(new Error("fail"));
      Object.defineProperty(navigator, "clipboard", {
        value: { writeText: vi.fn().mockRejectedValue(new Error("fail")) },
        configurable: true,
      });
      await profileStore.copyId("peer123");
      expect(uiStore.showToast).toHaveBeenCalledWith(t("profile.toast.copyFailed"));
    });
  });
});
