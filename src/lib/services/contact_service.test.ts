import { describe, it, expect, vi, beforeEach } from "vitest";
import { invokeMock } from "../../test-setup";
import {
  getContacts,
  getContactRequests,
  validatePeerId,
  sendContactRequest,
  connectToAddr,
  getMyInvite,
  acceptContactRequest,
  denyContactRequest,
  removeContact,
} from "./contact_service";

describe("contact_service", () => {
  beforeEach(() => {
    invokeMock.mockReset();
  });

  it("getContacts calls invoke('get_contacts')", async () => {
    invokeMock.mockResolvedValue([]);
    await getContacts();
    expect(invokeMock).toHaveBeenCalledWith("get_contacts");
  });

  it("getContactRequests calls invoke('get_contact_requests')", async () => {
    invokeMock.mockResolvedValue([]);
    await getContactRequests();
    expect(invokeMock).toHaveBeenCalledWith("get_contact_requests");
  });

  it("validatePeerId calls invoke with peerId", async () => {
    invokeMock.mockResolvedValue(true);
    await validatePeerId("12D3KooW...");
    expect(invokeMock).toHaveBeenCalledWith("validate_peer_id", {
      peerId: "12D3KooW...",
    });
  });

  it("sendContactRequest calls invoke with peerId and message", async () => {
    invokeMock.mockResolvedValue(undefined);
    await sendContactRequest("peer123", "Hi");
    expect(invokeMock).toHaveBeenCalledWith("send_contact_request", {
      peerId: "peer123",
      message: "Hi",
      addrHints: null,
    });
  });

  it("sendContactRequest passes addrHints when given", async () => {
    invokeMock.mockResolvedValue(undefined);
    await sendContactRequest("peer123", "Hi", ["/ip4/1.2.3.4/tcp/4001/p2p/peer123"]);
    expect(invokeMock).toHaveBeenCalledWith("send_contact_request", {
      peerId: "peer123",
      message: "Hi",
      addrHints: ["/ip4/1.2.3.4/tcp/4001/p2p/peer123"],
    });
  });

  it("connectToAddr calls invoke with input", async () => {
    invokeMock.mockResolvedValue("peer123");
    const result = await connectToAddr("noid:peer123@/ip4/1.2.3.4/tcp/4001/p2p/peer123");
    expect(invokeMock).toHaveBeenCalledWith("connect_to_addr", {
      input: "noid:peer123@/ip4/1.2.3.4/tcp/4001/p2p/peer123",
    });
    expect(result).toBe("peer123");
  });

  it("getMyInvite calls invoke('get_my_invite')", async () => {
    invokeMock.mockResolvedValue("noid:peer123@/ip4/1.2.3.4/tcp/4001/p2p/peer123");
    const result = await getMyInvite();
    expect(invokeMock).toHaveBeenCalledWith("get_my_invite");
    expect(result).toContain("noid:peer123");
  });

  it("acceptContactRequest calls invoke with peerId", async () => {
    invokeMock.mockResolvedValue(undefined);
    await acceptContactRequest("peer123");
    expect(invokeMock).toHaveBeenCalledWith("accept_contact_request", {
      peerId: "peer123",
    });
  });

  it("denyContactRequest calls invoke with peerId", async () => {
    invokeMock.mockResolvedValue(undefined);
    await denyContactRequest("peer123");
    expect(invokeMock).toHaveBeenCalledWith("deny_contact_request", {
      peerId: "peer123",
    });
  });

  it("removeContact calls invoke with peerId", async () => {
    invokeMock.mockResolvedValue(undefined);
    await removeContact("peer123");
    expect(invokeMock).toHaveBeenCalledWith("remove_contact", {
      peerId: "peer123",
    });
  });
});
