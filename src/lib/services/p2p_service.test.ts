import { describe, it, expect, vi, beforeEach } from "vitest";

const { listenMock } = vi.hoisted(() => ({
  listenMock: vi.fn(),
}));

vi.mock("@tauri-apps/api/event", () => ({ listen: listenMock }));

import {
  onChatMsg,
  onPeerConnected,
  onPeerDisconnected,
  onPeerOnline,
  onMessageFailed,
  onPendingMessagesSent,
  onMessageRead,
  onTypingIndicator,
  onP2PRequest,
} from "./p2p_service";

describe("p2p_service", () => {
  beforeEach(() => {
    listenMock.mockReset();
  });

  function setupListener() {
    const captured: { event: string; handler: (e: any) => void }[] = [];
    listenMock.mockImplementation(async (event: string, handler: (e: any) => void) => {
      captured.push({ event, handler });
      return () => {};
    });
    return captured;
  }

  it("onChatMsg listens to 'chat-msg' and calls cb with payload", async () => {
    const captured = setupListener();
    const cb = vi.fn();
    await onChatMsg(cb);
    expect(captured[0].event).toBe("chat-msg");
    captured[0].handler({ payload: { from: "peer1", data: "hello" } });
    expect(cb).toHaveBeenCalledWith({ from: "peer1", data: "hello" });
  });

  it("onPeerConnected listens to 'peer-connected'", async () => {
    const captured = setupListener();
    const cb = vi.fn();
    await onPeerConnected(cb);
    expect(captured[0].event).toBe("peer-connected");
    captured[0].handler({ payload: "peer1" });
    expect(cb).toHaveBeenCalledWith("peer1");
  });

  it("onPeerDisconnected listens to 'peer-disconnected'", async () => {
    const captured = setupListener();
    const cb = vi.fn();
    await onPeerDisconnected(cb);
    expect(captured[0].event).toBe("peer-disconnected");
    captured[0].handler({ payload: "peer1" });
    expect(cb).toHaveBeenCalledWith("peer1");
  });

  it("onPeerOnline listens to 'peer-online'", async () => {
    const captured = setupListener();
    const cb = vi.fn();
    await onPeerOnline(cb);
    expect(captured[0].event).toBe("peer-online");
    captured[0].handler({ payload: "peer1" });
    expect(cb).toHaveBeenCalledWith("peer1");
  });

  it("onMessageFailed listens to 'message-failed'", async () => {
    const captured = setupListener();
    const cb = vi.fn();
    await onMessageFailed(cb);
    expect(captured[0].event).toBe("message-failed");
    captured[0].handler({ payload: { to: "peer1", error: "timeout" } });
    expect(cb).toHaveBeenCalledWith({ to: "peer1", error: "timeout" });
  });

  it("onPendingMessagesSent listens to 'pending-messages-sent'", async () => {
    const captured = setupListener();
    const cb = vi.fn();
    await onPendingMessagesSent(cb);
    expect(captured[0].event).toBe("pending-messages-sent");
    captured[0].handler({ payload: "peer1" });
    expect(cb).toHaveBeenCalledWith("peer1");
  });

  it("onMessageRead listens to 'message-read'", async () => {
    const captured = setupListener();
    const cb = vi.fn();
    await onMessageRead(cb);
    expect(captured[0].event).toBe("message-read");
    captured[0].handler({ payload: { from: "peer1", message_id: "msg1" } });
    expect(cb).toHaveBeenCalledWith({ from: "peer1", message_id: "msg1" });
  });

  it("onTypingIndicator listens to 'typing-indicator'", async () => {
    const captured = setupListener();
    const cb = vi.fn();
    await onTypingIndicator(cb);
    expect(captured[0].event).toBe("typing-indicator");
    captured[0].handler({ payload: "peer1" });
    expect(cb).toHaveBeenCalledWith("peer1");
  });

  it("onP2PRequest listens to 'p2p-request'", async () => {
    const captured = setupListener();
    const cb = vi.fn();
    await onP2PRequest(cb);
    expect(captured[0].event).toBe("p2p-request");
    captured[0].handler({ payload: { from: "peer1" } });
    expect(cb).toHaveBeenCalledWith({ from: "peer1" });
  });
});
