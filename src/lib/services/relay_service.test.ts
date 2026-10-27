import { describe, it, expect, vi, beforeEach } from "vitest";
import { invokeMock } from "../../test-setup";

const { listenMock } = vi.hoisted(() => ({
  listenMock: vi.fn(),
}));

vi.mock("@tauri-apps/api/event", () => ({ listen: listenMock }));

import {
  getRelayConfig,
  getRelayStatus,
  setNodeRole,
  setPrivacyMode,
  onRelayStatus,
} from "./relay_service";
import type { RelayConfig, RelayStatus } from "$lib/relay";

const sampleConfig: RelayConfig = {
  role: "auto",
  privacy: "direct",
  listen_port: 4001,
  max_reservations: 128,
  max_reservations_per_peer: 4,
  reservation_duration_secs: 3600,
  max_circuits: 16,
  max_circuits_per_peer: 4,
  max_circuit_duration_secs: 120,
  max_circuit_bytes: 131072,
};

const sampleStatus: RelayStatus = {
  natStatus: "public",
  isRelaying: true,
  externalAddrs: ["/ip4/1.2.3.4/tcp/4001"],
  relayedAddrs: ["/ip4/1.2.3.4/tcp/4001/p2p/relay/p2p-circuit/p2p/me"],
  activeReservations: 1,
  inboundReservations: 3,
  activeCircuits: 2,
  knownRelays: 5,
  peersConnected: 7,
};

describe("relay_service", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    listenMock.mockReset();
  });

  it("getRelayConfig calls invoke('get_relay_config')", async () => {
    invokeMock.mockResolvedValue(sampleConfig);
    const result = await getRelayConfig();
    expect(invokeMock).toHaveBeenCalledWith("get_relay_config");
    expect(result).toEqual(sampleConfig);
  });

  it("getRelayStatus calls invoke('get_relay_status')", async () => {
    invokeMock.mockResolvedValue(sampleStatus);
    const result = await getRelayStatus();
    expect(invokeMock).toHaveBeenCalledWith("get_relay_status");
    expect(result).toEqual(sampleStatus);
  });

  it("setNodeRole passes role string", async () => {
    invokeMock.mockResolvedValue({ ...sampleConfig, role: "relay" });
    const result = await setNodeRole("relay");
    expect(invokeMock).toHaveBeenCalledWith("set_node_role", { role: "relay" });
    expect(result.role).toBe("relay");
  });

  it("setPrivacyMode passes mode string", async () => {
    invokeMock.mockResolvedValue({ ...sampleConfig, privacy: "relayed_only" });
    const result = await setPrivacyMode("relayed_only");
    expect(invokeMock).toHaveBeenCalledWith("set_privacy_mode", {
      mode: "relayed_only",
    });
    expect(result.privacy).toBe("relayed_only");
  });

  it("onRelayStatus listens to 'relay-status' and calls cb with payload", async () => {
    const captured: { event: string; handler: (e: any) => void }[] = [];
    listenMock.mockImplementation(async (event: string, handler: (e: any) => void) => {
      captured.push({ event, handler });
      return () => {};
    });
    const cb = vi.fn();
    await onRelayStatus(cb);
    expect(captured[0].event).toBe("relay-status");
    captured[0].handler({ payload: sampleStatus });
    expect(cb).toHaveBeenCalledWith(sampleStatus);
  });
});
