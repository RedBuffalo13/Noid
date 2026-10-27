import { describe, it, expect, vi, beforeEach } from "vitest";
import { invokeMock } from "../../test-setup";
import {
  getLastSyncTime,
  registerFolder,
  getSharedFolders,
  approveRoomMember,
} from "./settings_service";

describe("settings_service", () => {
  beforeEach(() => {
    invokeMock.mockReset();
  });

  it("getLastSyncTime calls invoke('get_last_sync_time')", async () => {
    invokeMock.mockResolvedValue("2024-01-01T00:00:00Z");
    const result = await getLastSyncTime();
    expect(invokeMock).toHaveBeenCalledWith("get_last_sync_time");
    expect(result).toBe("2024-01-01T00:00:00Z");
  });

  it("registerFolder calls invoke with path", async () => {
    invokeMock.mockResolvedValue(undefined);
    await registerFolder("/path/to/folder");
    expect(invokeMock).toHaveBeenCalledWith("register_folder", {
      path: "/path/to/folder",
    });
  });

  it("getSharedFolders calls invoke('get_shared_folders')", async () => {
    invokeMock.mockResolvedValue([]);
    await getSharedFolders();
    expect(invokeMock).toHaveBeenCalledWith("get_shared_folders");
  });

  it("approveRoomMember calls invoke with roomId and peerId", async () => {
    invokeMock.mockResolvedValue(undefined);
    await approveRoomMember("room1", "peer123");
    expect(invokeMock).toHaveBeenCalledWith("approve_room_member", {
      roomId: "room1",
      peerId: "peer123",
    });
  });
});
