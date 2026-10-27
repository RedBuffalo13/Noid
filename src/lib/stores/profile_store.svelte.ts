import { t } from "$lib/i18n/index.svelte";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { readFile } from "@tauri-apps/plugin-fs";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { uiStore } from "./ui_store.svelte";

let nickname = $state("NoidUser");
let avatar = $state<string | null>(null);

export const profileStore = {
  get nickname() { return nickname; },
  set nickname(val) { nickname = val; },
  get avatar() { return avatar; },
  set avatar(val) { avatar = val; },

  async loadProfile() {
    try {
      const [nick, av] = (await invoke("get_profile")) as any;
      if (nick) nickname = nick;
      avatar = av;
    } catch (e) {
      console.error("Profile load failed", e);
    }
  },

  async saveProfile() {
    try {
      await invoke("update_profile", { nickname, avatar });
      uiStore.resetNav("chats");
      uiStore.showToast(t("profile.toast.updated"));
    } catch (e) {
      console.error("Profile save failed", e);
      uiStore.showToast(t("profile.toast.saveFailed", { e: String(e) }));
    }
  },

  async pickAvatar() {
    try {
      const selected = await open({
        filters: [{ name: "Images", extensions: ["png", "jpg", "jpeg", "webp"] }],
        multiple: false,
      });

      if (selected && typeof selected === "string") {
        const bytes = await readFile(selected);
        const blob = new Blob([bytes]);
        const url = URL.createObjectURL(blob);

        const img = new Image();
        img.src = url;
        await new Promise((resolve, reject) => {
          img.onload = resolve;
          img.onerror = reject;
        });

        const canvas = document.createElement("canvas");
        const size = 320;
        canvas.width = size;
        canvas.height = size;
        const ctx = canvas.getContext("2d");

        if (ctx) {
          const minDim = Math.min(img.width, img.height);
          const sx = (img.width - minDim) / 2;
          const sy = (img.height - minDim) / 2;
          ctx.drawImage(img, sx, sy, minDim, minDim, 0, 0, size, size);
          avatar = canvas.toDataURL("image/jpeg", 0.7);
          console.log("Avatar cropped and resized");
        }
        URL.revokeObjectURL(url);
      }
    } catch (e) {
      console.error("Avatar error:", e);
      uiStore.showToast(t("profile.toast.imageInvalid"));
    }
  },

  async copyId(myId: string) {
    try {
      await writeText(myId);
      uiStore.showToast(t("profile.toast.idCopied"));
    } catch (e) {
      try {
        await navigator.clipboard.writeText(myId);
        uiStore.showToast(t("profile.toast.idCopied"));
      } catch (navErr) {
        uiStore.showToast(t("profile.toast.copyFailed"));
      }
    }
  }
};
