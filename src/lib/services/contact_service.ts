import { invoke } from "@tauri-apps/api/core";

export interface Contact {
  id: string;
  nickname: string;
  avatar: string | null;
  publicKey: Uint8Array | null;
  isBlocked: boolean;
}

export interface ContactRequest {
  senderId: string;
  message: string;
  nickname: string;
  avatar: string | null;
  timestamp: string;
}

export async function getContacts(): Promise<any[]> {
  return invoke("get_contacts");
}

export async function getContactRequests(): Promise<any[]> {
  return invoke("get_contact_requests");
}

export async function validatePeerId(peerId: string): Promise<boolean> {
  return invoke<boolean>("validate_peer_id", { peerId });
}

export async function sendContactRequest(peerId: string, message: string, addrHints?: string[]): Promise<void> {
  return invoke("send_contact_request", { peerId, message, addrHints: addrHints ?? null });
}

/** Join the network / reach a peer: accepts invite string, multiaddr or peer id. */
export async function connectToAddr(input: string): Promise<string> {
  return invoke<string>("connect_to_addr", { input });
}

/** This node's invite string (peer id + reachable addrs) for out-of-band sharing. */
export async function getMyInvite(): Promise<string> {
  return invoke<string>("get_my_invite");
}

export async function acceptContactRequest(peerId: string): Promise<void> {
  return invoke("accept_contact_request", { peerId });
}

export async function denyContactRequest(peerId: string): Promise<void> {
  return invoke("deny_contact_request", { peerId });
}

export async function removeContact(peerId: string): Promise<void> {
  return invoke("remove_contact", { peerId });
}

