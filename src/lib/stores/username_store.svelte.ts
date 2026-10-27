import { t } from "$lib/i18n/index.svelte";
import {
  setUsername as svcSetUsername,
  checkUsername as svcCheckUsername,
  lookupUser as svcLookupUser,
  lookupByPeerId as svcLookupByPeerId,
  getUsername as svcGetUsername,
} from "$lib/services/username_service";
import { sendContactRequest } from "$lib/services";
import { uiStore } from "./ui_store.svelte";
import type { UserRecord, UserSearchResult } from "$lib/types";

let username = $state<string | null>(null);
let isPublished = $state(false);
let searchQuery = $state("");
let searchResults = $state<UserSearchResult[]>([]);
let searching = $state(false);
let availabilityStatus = $state<"idle" | "checking" | "available" | "taken" | "unknown">("idle");

let checkTimer: ReturnType<typeof setTimeout> | null = null;

export const usernameStore = {
  get username() { return username; },
  get isPublished() { return isPublished; },
  get searchQuery() { return searchQuery; },
  set searchQuery(val) { searchQuery = val; },
  get searchResults() { return searchResults; },
  get searching() { return searching; },
  get availabilityStatus() { return availabilityStatus; },

  async loadUsername() {
    try {
      username = await svcGetUsername();
    } catch (e) {
      console.error("Failed to load username", e);
      username = null;
    }
  },

  async saveUsername(newUsername: string) {
    // FE-26: client-side check must mirror `validate_username` — check
    // availability only runs ≥3 chars, so a 1–2 char name would skip the
    // check AND pass a save it should never reach.
    if (newUsername.length < 3 || newUsername.length > 32) {
      uiStore.showToast(t("username.toast.tooShort"));
      return;
    }
    if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]*$/.test(newUsername)) {
      uiStore.showToast(t("username.toast.badChars"));
      return;
    }
    // D14: never publish while the availability verdict is unsettled or
    // negative — a blind publish is exactly the last-writer-wins flap the
    // audit flags (two owners re-publishing a taken name forever).
    if (availabilityStatus === "taken") {
      uiStore.showToast(t("username.toast.taken"));
      return;
    }
    if (availabilityStatus === "checking" || availabilityStatus === "unknown") {
      uiStore.showToast(t("username.toast.unverifiable"));
      return;
    }
    try {
      await svcSetUsername(newUsername);
      username = newUsername;
      isPublished = false;
      uiStore.showToast(t("username.toast.saving"));
    } catch (e) {
      uiStore.showToast(t("username.toast.error", { e: String(e) }));
    }
  },

  async checkAvailability(query: string) {
    if (!query || query.length < 3) {
      availabilityStatus = "idle";
      return;
    }

    availabilityStatus = "checking";

    if (checkTimer) clearTimeout(checkTimer);
    checkTimer = setTimeout(async () => {
      try {
        await svcCheckUsername(query);
      } catch (e) {
        console.error("Availability check failed", e);
        availabilityStatus = "idle";
      }
    }, 300);
  },

  handleAvailabilityResult(payload: { username: string; available: boolean; uncertain?: boolean }) {
    if (payload.uncertain) {
      availabilityStatus = "unknown";
    } else if (payload.available) {
      availabilityStatus = "available";
      if (payload.username === username) {
        isPublished = true;
      }
    } else {
      availabilityStatus = "taken";
    }
  },

  async searchUsers(query: string) {
    if (!query.trim()) {
      searchResults = [];
      return;
    }

    searching = true;
    searchResults = [];

    const trimmed = query.trim();

    // Detect Peer ID format (starts with 12D3KooW)
    if (trimmed.startsWith("12D3KooW")) {
      try {
        const connected = await svcLookupByPeerId(trimmed);
        if (connected) {
          searchResults = [
            {
              record: {
                peerId: trimmed,
                nickname: trimmed.slice(0, 12) + "...",
                shortId: trimmed.slice(8, 16),
                avatar: null,
              },
              source: "peer",
              isOnline: true,
            },
          ];
        }
        searching = false;
      } catch (e) {
        console.error("Peer ID lookup failed", e);
        searching = false;
      }
    } else {
      try {
        const cleanUsername = trimmed.split("#")[0];
        await svcLookupUser(cleanUsername);
      } catch (e) {
        console.error("User search failed", e);
        searching = false;
      }
    }
  },

  handleLookupResult(payload: { username: string; record: UserRecord | null }) {
    searching = false;
    if (payload.record) {
      searchResults = [
        {
          record: payload.record,
          source: "dht",
          isOnline: false,
        },
      ];
    } else {
      searchResults = [];
    }
  },

  async sendRequestToUser(record: UserRecord, message: string) {
    try {
      await sendContactRequest(record.peerId, message);
      uiStore.showToast(t("search.toast.sent"));
    } catch (e) {
      uiStore.showToast(t("search.toast.failed", { e: String(e) }));
    }
  },
};
