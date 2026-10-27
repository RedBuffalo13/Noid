import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export interface RoomMessagePayload {
  room_id: string;
  sender: string;
  content: string;
  msg_id: string;
  ts: string;
}

export interface RoomInvitePayload {
  room_id: string;
  from: string;
  /** Present on pending invites (offer phase) — the room's display name
   * and avatar announced by the inviter. */
  name?: string | null;
  avatar?: string | null;
}

/** A room invite awaiting user consent — the key arrives only on accept. */
export interface PendingRoomInvite {
  room_id: string;
  inviter: string;
  name: string | null;
  avatar: string | null;
}

export interface RoomInfo {
  id: string;
  name: string;
}

/** A room member with approval state and their announced profile. */
export interface MemberInfo {
  peerId: string;
  approved: boolean;
  name: string | null;
  avatar: string | null;
}

/** Decrypted room record + member list for the settings UI. */
export interface RoomDetails {
  id: string;
  name: string;
  avatar: string | null;
  owner: string | null;
  key_epoch: number;
  members: MemberInfo[];
}

/** Emitted on "room-updated" — kind: meta | members | key | removed. */
export interface RoomUpdatedPayload {
  room_id: string;
  kind: string;
}

/// Create an encrypted room — generates a stable room id and the AES-256
/// key locally. Invite contacts to share the key.
export async function createRoom(name: string): Promise<string> {
  return invoke("create_room", { name });
}

/// Join a room we were invited to (key already stored). Rooms cannot be
/// joined by bare id — the key only ever travels inside ratchet invites.
export async function joinRoom(roomId: string): Promise<void> {
  return invoke("join_room", { roomId });
}

export async function sendRoomMessage(roomId: string, content: string): Promise<void> {
  return invoke("send_room_message", { roomId, content });
}

export async function inviteToRoom(roomId: string, peerId: string): Promise<void> {
  return invoke("invite_to_room", { roomId, peerId });
}

/** Pending room invites awaiting consent — the key is delivered only
 * after accept. */
export async function listPendingRoomInvites(): Promise<PendingRoomInvite[]> {
  const rows = await invoke<[string, string, string | null, string | null][]>(
    "list_pending_room_invites",
  );
  return rows.map(([room_id, inviter, name, avatar]) => ({ room_id, inviter, name, avatar }));
}

/** Accept a pending invite — the inviter delivers the wrapped room key. */
export async function acceptRoomInvite(roomId: string): Promise<void> {
  return invoke("accept_room_invite", { roomId });
}

/** Decline a pending invite — the inviter drops us, no key is sent. */
export async function declineRoomInvite(roomId: string): Promise<void> {
  return invoke("decline_room_invite", { roomId });
}

export async function listRooms(): Promise<[string, string][]> {
  return invoke("list_rooms");
}

/** Decrypted room record + member list. Throws for unknown rooms. */
export async function getRoomInfo(roomId: string): Promise<RoomDetails> {
  return invoke("get_room_info", { roomId });
}

/** Owner-only rename — broadcasts the new name to all members. */
export async function renameRoom(roomId: string, name: string): Promise<void> {
  return invoke("rename_room", { roomId, name });
}

/** Owner-only avatar update — data-URL or null to clear. */
export async function setRoomAvatar(roomId: string, avatar: string | null): Promise<void> {
  return invoke("set_room_avatar", { roomId, avatar });
}

/** Owner-only kick — notifies the peer and rekeys the room. */
export async function removeRoomMember(roomId: string, peerId: string): Promise<void> {
  return invoke("remove_room_member", { roomId, peerId });
}

/** Leave a room — notifies the owner (triggers their rekey). */
export async function leaveRoom(roomId: string): Promise<void> {
  return invoke("leave_room", { roomId });
}

/** Owner-only delete — notifies members and wipes the room locally. */
export async function deleteRoom(roomId: string): Promise<void> {
  return invoke("delete_room", { roomId });
}

/// Room history: [msg_id, sender_peer_id, content, timestamp]
export async function getRoomMessages(roomId: string): Promise<[string, string, string, string][]> {
  return invoke("get_room_messages", { roomId });
}

export async function onRoomMessage(cb: (payload: RoomMessagePayload) => void): Promise<UnlistenFn> {
  return listen<RoomMessagePayload>("room-msg", (e) => cb(e.payload));
}

export async function onRoomInvite(cb: (payload: RoomInvitePayload) => void): Promise<UnlistenFn> {
  return listen<RoomInvitePayload>("room-invite", (e) => cb(e.payload));
}

/** Emitted when an accepted invite's key arrives and the room is
 * materialized locally — distinct from "room-invite" (the offer). */
export async function onRoomJoined(cb: (payload: RoomInvitePayload) => void): Promise<UnlistenFn> {
  return listen<RoomInvitePayload>("room-joined", (e) => cb(e.payload));
}

/** Meta/membership/key/lifecycle changes pushed by the backend. */
export async function onRoomUpdated(cb: (payload: RoomUpdatedPayload) => void): Promise<UnlistenFn> {
  return listen<RoomUpdatedPayload>("room-updated", (e) => cb(e.payload));
}
