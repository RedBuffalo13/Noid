import { describe, it, expect, vi, beforeEach } from "vitest";
import { invokeMock } from "../../test-setup";
import {
  setUsername,
  checkUsername,
  lookupUser,
  lookupByPeerId,
  getUsername,
} from "./username_service";

describe("username_service", () => {
  beforeEach(() => {
    invokeMock.mockReset();
  });

  it("setUsername calls invoke('set_username', {username})", async () => {
    invokeMock.mockResolvedValue(undefined);
    await setUsername("alice");
    expect(invokeMock).toHaveBeenCalledWith("set_username", { username: "alice" });
  });

  it("checkUsername calls invoke('check_username', {username})", async () => {
    invokeMock.mockResolvedValue(undefined);
    await checkUsername("alice");
    expect(invokeMock).toHaveBeenCalledWith("check_username", { username: "alice" });
  });

  it("lookupUser calls invoke('lookup_user', {username})", async () => {
    invokeMock.mockResolvedValue(undefined);
    await lookupUser("alice");
    expect(invokeMock).toHaveBeenCalledWith("lookup_user", { username: "alice" });
  });

  it("lookupByPeerId calls invoke('lookup_by_peer_id', {peerId})", async () => {
    invokeMock.mockResolvedValue(true);
    const result = await lookupByPeerId("12D3KooW...");
    expect(invokeMock).toHaveBeenCalledWith("lookup_by_peer_id", {
      peerId: "12D3KooW...",
    });
    expect(result).toBe(true);
  });

  it("getUsername calls invoke('get_username')", async () => {
    invokeMock.mockResolvedValue("alice");
    const result = await getUsername();
    expect(invokeMock).toHaveBeenCalledWith("get_username");
    expect(result).toBe("alice");
  });

  it("getUsername returns null when no username set", async () => {
    invokeMock.mockResolvedValue(null);
    const result = await getUsername();
    expect(result).toBeNull();
  });
});
