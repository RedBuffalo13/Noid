import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { t } from "$lib/i18n/index.svelte";

vi.mock("$lib/services/username_service", () => ({
  setUsername: vi.fn(),
  checkUsername: vi.fn(),
  lookupUser: vi.fn(),
  lookupByPeerId: vi.fn(),
  getUsername: vi.fn(),
}));

vi.mock("$lib/services", () => ({
  sendContactRequest: vi.fn(),
}));

vi.mock("./ui_store.svelte", () => ({
  uiStore: { showToast: vi.fn() },
}));

import { usernameStore } from "./username_store.svelte";
import {
  setUsername,
  checkUsername,
  lookupUser,
  lookupByPeerId,
  getUsername,
} from "$lib/services/username_service";
import { sendContactRequest } from "$lib/services";
import { uiStore } from "./ui_store.svelte";

describe("username_store", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe("loadUsername", () => {
    it("loads username from service", async () => {
      vi.mocked(getUsername).mockResolvedValue("alice");
      await usernameStore.loadUsername();
      expect(getUsername).toHaveBeenCalled();
      expect(usernameStore.username).toBe("alice");
    });

    it("sets username to null on error", async () => {
      vi.mocked(getUsername).mockRejectedValue(new Error("fail"));
      const spy = vi.spyOn(console, "error").mockImplementation(() => {});
      await usernameStore.loadUsername();
      expect(usernameStore.username).toBeNull();
      spy.mockRestore();
    });
  });

  describe("saveUsername", () => {
    it("saves username and shows toast", async () => {
      vi.mocked(setUsername).mockResolvedValue(undefined);
      await usernameStore.saveUsername("bob");
      expect(setUsername).toHaveBeenCalledWith("bob");
      expect(usernameStore.username).toBe("bob");
      expect(usernameStore.isPublished).toBe(false);
      expect(uiStore.showToast).toHaveBeenCalledWith(t("username.toast.saving"));
    });

    it("shows error toast on failure", async () => {
      vi.mocked(setUsername).mockRejectedValue(new Error("fail"));
      await usernameStore.saveUsername("bob");
      expect(uiStore.showToast).toHaveBeenCalledWith("Error: Error: fail");
    });
  });

  describe("checkAvailability", () => {
    it("sets status to idle for query < 3 chars", async () => {
      await usernameStore.checkAvailability("ab");
      expect(usernameStore.availabilityStatus).toBe("idle");
      expect(checkUsername).not.toHaveBeenCalled();
    });

    it("sets status to checking and calls checkUsername after debounce", async () => {
      vi.mocked(checkUsername).mockResolvedValue(undefined);
      usernameStore.checkAvailability("alice");
      expect(usernameStore.availabilityStatus).toBe("checking");
      vi.advanceTimersByTime(300);
      expect(checkUsername).toHaveBeenCalledWith("alice");
    });
  });

  describe("handleAvailabilityResult", () => {
    it("sets status to available and isPublished when username matches", () => {
      vi.mocked(getUsername).mockResolvedValue("alice");
      usernameStore.handleAvailabilityResult({ username: "alice", available: true });
      expect(usernameStore.availabilityStatus).toBe("available");
    });

    it("sets status to taken when not available", () => {
      usernameStore.handleAvailabilityResult({ username: "alice", available: false });
      expect(usernameStore.availabilityStatus).toBe("taken");
    });
  });

  describe("searchUsers", () => {
    it("clears results for empty query", async () => {
      await usernameStore.searchUsers("   ");
      expect(usernameStore.searchResults).toEqual([]);
    });

    it("uses lookupByPeerId for Peer ID format", async () => {
      vi.mocked(lookupByPeerId).mockResolvedValue(true);
      await usernameStore.searchUsers("12D3KooWabc");
      expect(lookupByPeerId).toHaveBeenCalledWith("12D3KooWabc");
      expect(usernameStore.searchResults.length).toBe(1);
      expect(usernameStore.searchResults[0].source).toBe("peer");
    });

    it("uses lookupUser for username format", async () => {
      vi.mocked(lookupUser).mockResolvedValue(undefined);
      await usernameStore.searchUsers("alice");
      expect(lookupUser).toHaveBeenCalledWith("alice");
    });

    it("strips #short_id suffix for username lookup", async () => {
      vi.mocked(lookupUser).mockResolvedValue(undefined);
      await usernameStore.searchUsers("alice#1234");
      expect(lookupUser).toHaveBeenCalledWith("alice");
    });
  });

  describe("handleLookupResult", () => {
    it("sets searchResults when record is present", () => {
      usernameStore.handleLookupResult({
        username: "alice",
        record: { peerId: "peer1", nickname: "alice", avatar: null, shortId: "1234" },
      });
      expect(usernameStore.searchResults.length).toBe(1);
      expect(usernameStore.searchResults[0].source).toBe("dht");
    });

    it("clears searchResults when record is null", () => {
      usernameStore.handleLookupResult({ username: "alice", record: null });
      expect(usernameStore.searchResults).toEqual([]);
    });
  });

  describe("sendRequestToUser", () => {
    it("sends contact request and shows toast", async () => {
      vi.mocked(sendContactRequest).mockResolvedValue(undefined);
      await usernameStore.sendRequestToUser(
        { peerId: "peer1", nickname: "alice", avatar: null, shortId: "1234" },
        "Hi"
      );
      expect(sendContactRequest).toHaveBeenCalledWith("peer1", "Hi");
      expect(uiStore.showToast).toHaveBeenCalledWith("Contact request sent");
    });

    it("shows error toast on failure", async () => {
      vi.mocked(sendContactRequest).mockRejectedValue(new Error("fail"));
      await usernameStore.sendRequestToUser(
        { peerId: "peer1", nickname: "alice", avatar: null, shortId: "1234" },
        "Hi"
      );
      expect(uiStore.showToast).toHaveBeenCalledWith("Failed to send request: Error: fail");
    });
  });
});
