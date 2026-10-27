import { describe, it, expect, vi, beforeEach } from "vitest";

const { invokeMock, openMock } = vi.hoisted(() => ({
  invokeMock: vi.fn(),
  openMock: vi.fn(),
}));

vi.mock("@tauri-apps/api/core", () => ({ invoke: invokeMock }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: openMock }));

vi.mock("$lib/services/folder_service", () => ({
  updateFolderPath: vi.fn(),
  updateFolderVisibility: vi.fn(),
  updateFolderPassword: vi.fn(),
  deleteSharedFolder: vi.fn(),
  searchSharedFolders: vi.fn(),
}));

vi.mock("./ui_store.svelte", () => ({
  uiStore: { showToast: vi.fn() },
}));

import { folderStore } from "./folder_store.svelte";
import { uiStore } from "./ui_store.svelte";
import {
  updateFolderPath,
  updateFolderVisibility,
  updateFolderPassword,
  deleteSharedFolder,
  searchSharedFolders,
} from "$lib/services/folder_service";

describe("folder_store", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    openMock.mockReset();
    vi.clearAllMocks();
  });

  describe("loadFolders", () => {
    it("loads folders from invoke", async () => {
      invokeMock.mockResolvedValue([["id1", "/path1", true]]);
      await folderStore.loadFolders();
      expect(invokeMock).toHaveBeenCalledWith("get_shared_folders");
      expect(folderStore.folders).toEqual([["id1", "/path1", true]]);
    });

    it("clears folders on error", async () => {
      invokeMock.mockRejectedValue(new Error("fail"));
      const spy = vi.spyOn(console, "error").mockImplementation(() => {});
      await folderStore.loadFolders();
      expect(folderStore.folders).toEqual([]);
      spy.mockRestore();
    });
  });

  describe("pickFolder", () => {
    it("returns selected path and sets selectedPath", async () => {
      openMock.mockResolvedValue("/selected/path");
      const result = await folderStore.pickFolder();
      expect(result).toBe("/selected/path");
      expect(folderStore.selectedPath).toBe("/selected/path");
    });

    it("returns null when dialog returns null", async () => {
      openMock.mockResolvedValue(null);
      const result = await folderStore.pickFolder();
      expect(result).toBeNull();
    });

    it("shows toast on error", async () => {
      openMock.mockRejectedValue(new Error("fail"));
      const result = await folderStore.pickFolder();
      expect(result).toBeNull();
      expect(uiStore.showToast).toHaveBeenCalledWith("Failed to open folder dialog");
    });
  });

  describe("registerFolder", () => {
    it("shows toast when path is empty", async () => {
      folderStore.selectedPath = "   ";
      await folderStore.registerFolder();
      expect(uiStore.showToast).toHaveBeenCalledWith("Please select a folder first");
    });

    it("registers folder and reloads", async () => {
      invokeMock.mockResolvedValue(undefined);
      folderStore.selectedPath = "/path";
      await folderStore.registerFolder("/path");
      expect(invokeMock).toHaveBeenCalledWith("register_folder", { path: "/path" });
      expect(uiStore.showToast).toHaveBeenCalledWith("Folder registered");
    });
  });

  describe("updatePath", () => {
    it("calls updateFolderPath with new path", async () => {
      openMock.mockResolvedValue("/new/path");
      vi.mocked(updateFolderPath).mockResolvedValue(undefined);
      invokeMock.mockResolvedValue([]);
      await folderStore.updatePath("folder1");
      expect(updateFolderPath).toHaveBeenCalledWith("folder1", "/new/path");
    });
  });

  describe("toggleVisibility", () => {
    it("calls updateFolderVisibility", async () => {
      vi.mocked(updateFolderVisibility).mockResolvedValue(undefined);
      invokeMock.mockResolvedValue([]);
      await folderStore.toggleVisibility("folder1", true);
      expect(updateFolderVisibility).toHaveBeenCalledWith("folder1", true);
    });
  });

  describe("setPassword", () => {
    it("calls updateFolderPassword", async () => {
      vi.mocked(updateFolderPassword).mockResolvedValue(undefined);
      invokeMock.mockResolvedValue([]);
      await folderStore.setPassword("folder1", "secret");
      expect(updateFolderPassword).toHaveBeenCalledWith("folder1", "secret");
      expect(uiStore.showToast).toHaveBeenCalledWith("Password set");
    });

    it("shows Password removed when password is empty", async () => {
      vi.mocked(updateFolderPassword).mockResolvedValue(undefined);
      invokeMock.mockResolvedValue([]);
      await folderStore.setPassword("folder1", "");
      expect(uiStore.showToast).toHaveBeenCalledWith("Password removed");
    });
  });

  describe("removeFolder", () => {
    it("calls deleteSharedFolder", async () => {
      vi.mocked(deleteSharedFolder).mockResolvedValue(undefined);
      invokeMock.mockResolvedValue([]);
      await folderStore.removeFolder("folder1");
      expect(deleteSharedFolder).toHaveBeenCalledWith("folder1");
    });
  });

  describe("search", () => {
    it("clears results for empty query", async () => {
      await folderStore.search("   ");
      expect(searchSharedFolders).not.toHaveBeenCalled();
    });

    it("calls searchSharedFolders for non-empty query", async () => {
      vi.mocked(searchSharedFolders).mockResolvedValue([]);
      await folderStore.search("test");
      expect(searchSharedFolders).toHaveBeenCalledWith("test");
    });
  });
});
