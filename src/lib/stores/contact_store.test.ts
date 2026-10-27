import { describe, it, expect, vi, beforeEach } from "vitest";
import { t } from "$lib/i18n/index.svelte";

vi.mock("$lib/services", () => ({
  getContacts: vi.fn(),
  getContactRequests: vi.fn(),
  validatePeerId: vi.fn(),
  sendContactRequest: vi.fn(),
  acceptContactRequest: vi.fn(),
  denyContactRequest: vi.fn(),
  removeContact: vi.fn(),
  getChatMessages: vi.fn(),
}));

vi.mock("./ui_store.svelte", () => ({
  uiStore: { showToast: vi.fn(), subPage: "chats" },
}));

vi.mock("./chat_store.svelte", () => ({
  chatStore: { getUnread: vi.fn().mockReturnValue(0) },
}));

import { contactStore } from "./contact_store.svelte";
import {
  getContacts,
  getContactRequests,
  validatePeerId,
  sendContactRequest,
  acceptContactRequest,
  denyContactRequest,
  removeContact,
  getChatMessages,
} from "$lib/services";
import { uiStore } from "./ui_store.svelte";

describe("contact_store", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("setOnline / setOffline", () => {
    it("setOnline updates onlinePeers reactively without a reload", () => {
      contactStore.setOnline("peer1");
      expect(contactStore.onlinePeers.has("peer1")).toBe(true);
      // FE-18: the SvelteSet IS the update — a presence flip must not
      // trigger a contacts reload.
      expect(getContacts).not.toHaveBeenCalled();
    });

    it("setOffline removes from onlinePeers reactively", () => {
      contactStore.setOnline("peer1");
      contactStore.setOffline("peer1");
      expect(contactStore.onlinePeers.has("peer1")).toBe(false);
      expect(getContacts).not.toHaveBeenCalled();
    });
  });

  describe("loadContacts", () => {
    it("loads contacts and builds chatList", async () => {
      vi.mocked(getContacts).mockResolvedValue([
        ["peer1", "Alice", null],
        ["peer2", "Bob", "avatar-data"],
      ]);
      vi.mocked(getContactRequests).mockResolvedValue([]);
      vi.mocked(getChatMessages).mockResolvedValue([]);
      await contactStore.loadContacts();
      expect(getContacts).toHaveBeenCalled();
      expect(getContactRequests).toHaveBeenCalled();
    });

    it("handles error gracefully", async () => {
      vi.mocked(getContacts).mockRejectedValue(new Error("fail"));
      const spy = vi.spyOn(console, "error").mockImplementation(() => {});
      await contactStore.loadContacts();
      spy.mockRestore();
    });
  });

  describe("sendRequest", () => {
    it("shows toast when peerId is empty", async () => {
      contactStore.requestPeerId = "   ";
      await contactStore.sendRequest();
      expect(validatePeerId).not.toHaveBeenCalled();
      expect(uiStore.showToast).toHaveBeenCalledWith(t("contacts.toast.needPeerId"));
    });

    it("shows toast when peerId is invalid", async () => {
      contactStore.requestPeerId = "invalid";
      vi.mocked(validatePeerId).mockResolvedValue(false);
      await contactStore.sendRequest();
      expect(uiStore.showToast).toHaveBeenCalledWith(t("contacts.toast.badPeerId"));
    });

    it("sends request on valid peerId", async () => {
      contactStore.requestPeerId = "12D3KooW...";
      vi.mocked(validatePeerId).mockResolvedValue(true);
      vi.mocked(sendContactRequest).mockResolvedValue(undefined);
      await contactStore.sendRequest();
      expect(sendContactRequest).toHaveBeenCalled();
      expect(uiStore.showToast).toHaveBeenCalledWith(t("contacts.toast.requestSent"));
    });
  });

  describe("acceptRequest", () => {
    it("validates and accepts", async () => {
      vi.mocked(validatePeerId).mockResolvedValue(true);
      vi.mocked(acceptContactRequest).mockResolvedValue(undefined);
      vi.mocked(getContacts).mockResolvedValue([]);
      vi.mocked(getContactRequests).mockResolvedValue([]);
      await contactStore.acceptRequest("peer1");
      expect(acceptContactRequest).toHaveBeenCalledWith("peer1");
    });

    it("shows toast on invalid peerId", async () => {
      vi.mocked(validatePeerId).mockResolvedValue(false);
      await contactStore.acceptRequest("bad");
      expect(uiStore.showToast).toHaveBeenCalledWith(t("contacts.toast.badPeerId"));
    });
  });

  describe("denyRequest", () => {
    it("validates and denies", async () => {
      vi.mocked(validatePeerId).mockResolvedValue(true);
      vi.mocked(denyContactRequest).mockResolvedValue(undefined);
      vi.mocked(getContacts).mockResolvedValue([]);
      vi.mocked(getContactRequests).mockResolvedValue([]);
      await contactStore.denyRequest("peer1");
      expect(denyContactRequest).toHaveBeenCalledWith("peer1");
    });
  });

  describe("deleteContact", () => {
    it("calls removeContact and reloads", async () => {
      vi.mocked(removeContact).mockResolvedValue(undefined);
      vi.mocked(getContacts).mockResolvedValue([]);
      vi.mocked(getContactRequests).mockResolvedValue([]);
      await contactStore.deleteContact("peer1");
      expect(removeContact).toHaveBeenCalledWith("peer1");
      expect(uiStore.showToast).toHaveBeenCalledWith(t("contacts.toast.deleted"));
    });
  });
});
