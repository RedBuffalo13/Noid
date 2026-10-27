import { t } from "$lib/i18n/index.svelte";
import { open } from "@tauri-apps/plugin-dialog";
import { invoke } from "@tauri-apps/api/core";
import {
  updateFolderPath as svcUpdateFolderPath,
  updateFolderVisibility as svcUpdateFolderVisibility,
  updateFolderPassword as svcUpdateFolderPassword,
  deleteSharedFolder as svcDeleteSharedFolder,
  searchSharedFolders as svcSearchSharedFolders,
} from "$lib/services/folder_service";
import { uiStore } from "./ui_store.svelte";

let folders = $state<[string, string, boolean][]>([]);
let searchQuery = $state("");
let searchResults = $state<[string, string, boolean, string | null][]>([]);
let selectedPath = $state("");

export const folderStore = {
  get folders() { return folders; },
  get searchQuery() { return searchQuery; },
  set searchQuery(val) { searchQuery = val; },
  get searchResults() { return searchResults; },
  get selectedPath() { return selectedPath; },
  set selectedPath(val) { selectedPath = val; },

  async loadFolders() {
    try {
      folders = (await invoke("get_shared_folders")) as [string, string, boolean][];
    } catch (e) {
      console.error("Failed to load folders", e);
      folders = [];
    }
  },

  async pickFolder(): Promise<string | null> {
    try {
      const selected = await open({ directory: true, multiple: false });
      if (selected && typeof selected === "string") {
        selectedPath = selected;
        return selected;
      }
    } catch (e) {
      console.error("Folder pick failed:", e);
      uiStore.showToast(t("folders.toast.dialogFailed"));
    }
    return null;
  },

  async registerFolder(path?: string) {
    const folderPath = path || selectedPath;
    if (!folderPath?.trim()) {
      uiStore.showToast(t("folders.toast.selectFirst"));
      return;
    }
    try {
      await invoke("register_folder", { path: folderPath.trim() });
      uiStore.showToast(t("folders.toast.registered"));
      selectedPath = "";
      await this.loadFolders();
    } catch (e) {
      console.error("Failed to register folder:", e);
      uiStore.showToast(t("folders.toast.registerFailed"));
    }
  },

  async updatePath(id: string) {
    const newPath = await this.pickFolder();
    if (!newPath) return;
    try {
      await svcUpdateFolderPath(id, newPath);
      uiStore.showToast(t("folders.toast.pathUpdated"));
      await this.loadFolders();
    } catch (e) {
      uiStore.showToast(t("folders.toast.error", { e: String(e) }));
    }
  },

  async toggleVisibility(id: string, isPublic: boolean) {
    try {
      await svcUpdateFolderVisibility(id, isPublic);
      await this.loadFolders();
    } catch (e) {
      uiStore.showToast(t("folders.toast.error", { e: String(e) }));
    }
  },

  async setPassword(id: string, password: string) {
    try {
      await svcUpdateFolderPassword(id, password);
      uiStore.showToast(password ? t("folders.toast.passwordSet") : t("folders.toast.passwordRemoved"));
      await this.loadFolders();
    } catch (e) {
      uiStore.showToast(t("folders.toast.error", { e: String(e) }));
    }
  },

  async removeFolder(id: string) {
    try {
      await svcDeleteSharedFolder(id);
      uiStore.showToast(t("folders.toast.deleted"));
      await this.loadFolders();
    } catch (e) {
      uiStore.showToast(t("folders.toast.error", { e: String(e) }));
    }
  },

  async search(query: string) {
    if (!query.trim()) {
      searchResults = [];
      return;
    }
    try {
      searchResults = await svcSearchSharedFolders(query);
    } catch (e) {
      console.error("Search failed:", e);
      searchResults = [];
    }
  },
};
