import { describe, it, expect, vi, beforeEach } from "vitest";
import { t } from "$lib/i18n/index.svelte";

vi.mock("$lib/services", () => ({
  getChatMessages: vi.fn(),
  getNewMessagesSince: vi.fn(),
  getAllMissedMessages: vi.fn(),
  sendChatMessage: vi.fn(),
  sendTypingIndicator: vi.fn(),
  getPendingMessageIds: vi.fn().mockResolvedValue([]),
  deleteChat: vi.fn(),
}));

vi.mock("./ui_store.svelte", () => ({
  uiStore: { showToast: vi.fn() },
}));

vi.mock("svelte", () => ({
  tick: () => Promise.resolve(),
}));

import { chatStore } from "./chat_store.svelte";
import {
  getChatMessages,
  getNewMessagesSince,
  getAllMissedMessages,
  sendChatMessage,
} from "$lib/services";
import { uiStore } from "./ui_store.svelte";

describe("chat_store", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    chatStore.messages = [];
    chatStore.currentPeer = "";
    chatStore.inputMsg = "";
    chatStore.myId = "";
  });

  describe("loadMessages", () => {
    it("maps tuples to Message[] and clears unread", async () => {
      vi.mocked(getChatMessages).mockResolvedValue([
        ["msg1", "me", "hello", "2024-01-01T00:00:00.000Z"],
        ["msg2", "peer1", "hi", "2024-01-01T00:01:00.000Z"],
      ]);
      chatStore.myId = "me";
      chatStore.currentPeer = "peer1";
      await chatStore.loadMessages("peer1");
      expect(chatStore.messages.length).toBe(2);
      expect(chatStore.messages[0].from).toBe("Me");
      expect(chatStore.messages[1].from).toBe("peer1");
    });

    it("clears messages on error", async () => {
      vi.mocked(getChatMessages).mockRejectedValue(new Error("fail"));
      chatStore.messages = [{ from: "x", content: "y", type: "sent", timestamp: 0 }];
      await chatStore.loadMessages("peer1");
      expect(chatStore.messages).toEqual([]);
    });
  });

  describe("sendMessage", () => {
    it("does nothing with empty input", async () => {
      chatStore.inputMsg = "   ";
      await chatStore.sendMessage();
      expect(sendChatMessage).not.toHaveBeenCalled();
    });

    it("adds message with sending status and updates to sent on success", async () => {
      vi.mocked(sendChatMessage).mockResolvedValue("msg-uuid-1");
      chatStore.currentPeer = "peer1";
      chatStore.inputMsg = "hello";
      await chatStore.sendMessage();
      expect(chatStore.messages.length).toBe(1);
      expect(chatStore.messages[0].status).toBe("sent");
      // FE-23: the optimistic bubble now carries the real message id.
      expect(chatStore.messages[0].id).toBe("msg-uuid-1");
    });

    it("marks message as failed on error", async () => {
      vi.mocked(sendChatMessage).mockRejectedValue(new Error("fail"));
      chatStore.currentPeer = "peer1";
      chatStore.inputMsg = "hello";
      await chatStore.sendMessage();
      expect(chatStore.messages.length).toBe(1);
      expect(chatStore.messages[0].status).toBe("failed");
      expect(uiStore.showToast).toHaveBeenCalledWith(t("chat.toast.sendFailed"));
    });
  });

  describe("appendMessage", () => {
    it("adds message to list", () => {
      const msg = { from: "peer1", content: "hi", type: "received" as const, timestamp: 0 };
      chatStore.appendMessage(msg);
      expect(chatStore.messages.length).toBe(1);
    });
  });

  describe("markDeliveredToCurrentPeer", () => {
    it("updates sent messages to delivered", () => {
      chatStore.messages = [
        { from: "Me", content: "a", type: "sent", timestamp: 0, status: "sent" as const },
        { from: "peer", content: "b", type: "received", timestamp: 0 },
      ];
      chatStore.markDeliveredToCurrentPeer();
      expect(chatStore.messages[0].status).toBe("delivered");
      expect(chatStore.messages[0].delivered).toBe(true);
    });
  });

  describe("markFailed", () => {
    it("marks sent messages as failed for matching peer", () => {
      chatStore.currentPeer = "peer1";
      chatStore.messages = [
        { from: "Me", content: "a", type: "sent", timestamp: 0, status: "sent" as const, delivered: true },
      ];
      chatStore.markFailed("peer1");
      expect(chatStore.messages[0].status).toBe("failed");
      expect(chatStore.messages[0].delivered).toBe(false);
    });
  });

  describe("markPendingSent", () => {
    it("sets delivered=true for undelivered sent messages", () => {
      chatStore.currentPeer = "peer1";
      chatStore.messages = [
        { from: "Me", content: "a", type: "sent", timestamp: 0, delivered: false },
      ];
      chatStore.markPendingSent("peer1");
      expect(chatStore.messages[0].delivered).toBe(true);
    });
  });

  describe("checkMissedMessagesFromPeer", () => {
    it("does nothing when peer doesn't match currentPeer", async () => {
      chatStore.currentPeer = "peer1";
      await chatStore.checkMissedMessagesFromPeer("peer2");
      expect(getNewMessagesSince).not.toHaveBeenCalled();
    });

    it("fetches and appends new messages when peer matches", async () => {
      vi.mocked(getNewMessagesSince).mockResolvedValue([
        ["msg1", "peer1", "hello", "2024-01-01T00:00:00.000Z"],
      ]);
      chatStore.currentPeer = "peer1";
      chatStore.myId = "me";
      await chatStore.checkMissedMessagesFromPeer("peer1");
      expect(getNewMessagesSince).toHaveBeenCalled();
      expect(chatStore.messages.length).toBe(1);
    });
  });

  describe("checkAllMissedMessages", () => {
    it("fetches and appends missed messages for currentPeer", async () => {
      vi.mocked(getAllMissedMessages).mockResolvedValue({
        peer1: [["msg1", "peer1", "hello", "2024-01-01T00:00:00.000Z"]],
      });
      chatStore.currentPeer = "peer1";
      chatStore.myId = "me";
      await chatStore.checkAllMissedMessages();
      expect(getAllMissedMessages).toHaveBeenCalled();
      expect(chatStore.messages.length).toBe(1);
    });
  });

  describe("refreshCurrentChat", () => {
    it("does nothing when no currentPeer", async () => {
      chatStore.currentPeer = "";
      await chatStore.refreshCurrentChat();
      expect(getChatMessages).not.toHaveBeenCalled();
    });

    it("reloads when message count differs", async () => {
      vi.mocked(getChatMessages).mockResolvedValue([
        ["msg1", "me", "hello", "2024-01-01T00:00:00.000Z"],
        ["msg2", "peer1", "hi", "2024-01-01T00:01:00.000Z"],
      ]);
      chatStore.currentPeer = "peer1";
      chatStore.myId = "me";
      chatStore.messages = [{ from: "Me", content: "old", type: "sent", timestamp: 0 }];
      await chatStore.refreshCurrentChat();
      expect(chatStore.messages.length).toBe(2);
    });
  });

  describe("unread management", () => {
    it("incrementUnread increments count", () => {
      chatStore.incrementUnread("peer1");
      expect(chatStore.getUnread("peer1")).toBe(1);
      chatStore.incrementUnread("peer1");
      expect(chatStore.getUnread("peer1")).toBe(2);
    });

    it("clearUnread resets to 0", () => {
      chatStore.incrementUnread("peer1");
      chatStore.clearUnread("peer1");
      expect(chatStore.getUnread("peer1")).toBe(0);
    });

    it("getUnread returns 0 for unknown peer", () => {
      expect(chatStore.getUnread("unknown")).toBe(0);
    });
  });
});
