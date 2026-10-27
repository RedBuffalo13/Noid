import { describe, it, expect, vi, beforeEach } from "vitest";
import { invokeMock } from "../../test-setup";
import {
  getChatMessages,
  getNewMessagesSince,
  getAllMissedMessages,
  sendChatMessage,
  sendReadReceipt,
  sendTypingIndicator,
} from "./chat_service";

describe("chat_service", () => {
  beforeEach(() => {
    invokeMock.mockReset();
  });

  it("getChatMessages calls invoke('get_chat_messages', {peerId})", async () => {
    invokeMock.mockResolvedValue([]);
    await getChatMessages("peer123");
    expect(invokeMock).toHaveBeenCalledWith("get_chat_messages", { peerId: "peer123" });
  });

  it("getNewMessagesSince calls invoke with peerId and sinceTime", async () => {
    invokeMock.mockResolvedValue([]);
    await getNewMessagesSince("peer123", "2024-01-01T00:00:00Z");
    expect(invokeMock).toHaveBeenCalledWith("get_new_messages_since", {
      peerId: "peer123",
      sinceTime: "2024-01-01T00:00:00Z",
    });
  });

  it("getAllMissedMessages calls invoke('get_all_missed_messages')", async () => {
    invokeMock.mockResolvedValue({});
    await getAllMissedMessages();
    expect(invokeMock).toHaveBeenCalledWith("get_all_missed_messages");
  });

  it("sendChatMessage calls invoke with peerId and content", async () => {
    invokeMock.mockResolvedValue(undefined);
    await sendChatMessage("peer123", "hello");
    expect(invokeMock).toHaveBeenCalledWith("send_chat_message", {
      peerId: "peer123",
      content: "hello",
    });
  });

  it("sendReadReceipt calls invoke with peerId and messageId", async () => {
    invokeMock.mockResolvedValue(undefined);
    await sendReadReceipt("peer123", "msg456");
    expect(invokeMock).toHaveBeenCalledWith("send_read_receipt", {
      peerId: "peer123",
      messageId: "msg456",
    });
  });

  it("sendTypingIndicator calls invoke with peerId", async () => {
    invokeMock.mockResolvedValue(undefined);
    await sendTypingIndicator("peer123");
    expect(invokeMock).toHaveBeenCalledWith("send_typing_indicator", {
      peerId: "peer123",
    });
  });
});
