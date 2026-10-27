import { describe, it, expect, vi, beforeEach } from "vitest";
import { invokeMock } from "../../test-setup";
import { joinRoom, sendRoomMessage, inviteToRoom } from "./room_service";

describe("room_service", () => {
  beforeEach(() => {
    invokeMock.mockReset();
  });

  it("joinRoom calls invoke('join_room', {roomId})", async () => {
    invokeMock.mockResolvedValue(undefined);
    await joinRoom("room1");
    expect(invokeMock).toHaveBeenCalledWith("join_room", { roomId: "room1" });
  });

  it("sendRoomMessage calls invoke with roomId and content", async () => {
    invokeMock.mockResolvedValue(undefined);
    await sendRoomMessage("room1", "hello");
    expect(invokeMock).toHaveBeenCalledWith("send_room_message", {
      roomId: "room1",
      content: "hello",
    });
  });

  it("inviteToRoom calls invoke with roomId and peerId", async () => {
    invokeMock.mockResolvedValue(undefined);
    await inviteToRoom("room1", "peer123");
    expect(invokeMock).toHaveBeenCalledWith("invite_to_room", {
      roomId: "room1",
      peerId: "peer123",
    });
  });
});
