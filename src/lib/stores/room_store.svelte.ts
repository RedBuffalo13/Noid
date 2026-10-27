import { t } from "$lib/i18n/index.svelte";
import type { UnlistenFn } from "@tauri-apps/api/event";
import {
  getRoomInfo,
  inviteToRoom,
  leaveRoom,
  deleteRoom,
  removeRoomMember,
  renameRoom,
  setRoomAvatar,
  listRooms,
  onRoomUpdated,
  onRoomInvite,
  onRoomJoined,
  listPendingRoomInvites,
  acceptRoomInvite,
  declineRoomInvite,
  type RoomDetails,
  type PendingRoomInvite,
} from "$lib/services/room_service";
import { approveRoomMember } from "$lib/services/settings_service";
import { pickImageDataUrl } from "$lib/utils/image";
import { uiStore } from "./ui_store.svelte";

let rooms = $state<[string, string][]>([]);
let current = $state<RoomDetails | null>(null);
let pendingInvites = $state<PendingRoomInvite[]>([]);

/** The peer id of the local user — set by MainScreen once known. */
let myId = $state("");

export const roomStore = {
  get rooms() { return rooms; },
  set rooms(val) { rooms = val; },
  get current() { return current; },
  get myId() { return myId; },
  set myId(val) { myId = val; },
  /** True when we own the currently open room (owner-only controls). */
  get isOwner() { return !!current && current.owner === myId; },
  /** True when the current room has no recorded owner — legacy rooms
   * stay unmanaged until the owner's Meta{owner} announcement lands. */
  get ownerless() { return !!current && !current.owner; },
  /** Room invites awaiting user consent — key arrives only on accept. */
  get pendingInvites() { return pendingInvites; },

  /** Best-known display name for a member of the open room — announced
   * member profile first, bare peer id as fallback. */
  memberName(peerId: string): string | null {
    return current?.members.find((m) => m.peerId === peerId)?.name ?? null;
  },

  /** Best-known avatar for a member of the open room. */
  memberAvatar(peerId: string): string | null {
    return current?.members.find((m) => m.peerId === peerId)?.avatar ?? null;
  },

  async loadRooms() {
    try {
      rooms = await listRooms();
    } catch (e) {
      console.error("Failed to load rooms:", e);
    }
  },

  async loadPendingInvites() {
    try {
      pendingInvites = await listPendingRoomInvites();
    } catch (e) {
      console.error("Failed to load pending room invites:", e);
    }
  },

  async acceptInvite(roomId: string) {
    await acceptRoomInvite(roomId);
    pendingInvites = pendingInvites.filter((i) => i.room_id !== roomId);
    uiStore.showToast(t("room.toast.inviteAccepted"));
  },

  async declineInvite(roomId: string) {
    await declineRoomInvite(roomId);
    pendingInvites = pendingInvites.filter((i) => i.room_id !== roomId);
    uiStore.showToast(t("room.toast.inviteDeclined"));
  },

  /** Open a room's settings — loads details; throws to the caller on
   * unknown rooms so the UI can toast. */
  async openSettings(roomId: string) {
    current = await getRoomInfo(roomId);
  },

  async refresh() {
    if (!current) return;
    try {
      current = await getRoomInfo(current.id);
    } catch {
      // Room was deleted/removed locally — close settings.
      current = null;
      uiStore.resetNav("chats");
    }
  },

  async rename(name: string) {
    if (!current) return;
    await renameRoom(current.id, name.trim());
    await this.refresh();
    uiStore.showToast(t("room.toast.renamed"));
  },

  async pickAvatar() {
    if (!current) return;
    try {
      const dataUrl = await pickImageDataUrl(320);
      if (!dataUrl) return;
      await setRoomAvatar(current.id, dataUrl);
      await this.refresh();
      uiStore.showToast(t("room.toast.avatarUpdated"));
    } catch (e) {
      console.error("Room avatar failed:", e);
      uiStore.showToast(t("room.toast.avatarInvalid"));
    }
  },

  async invite(peerId: string) {
    if (!current) return;
    await inviteToRoom(current.id, peerId);
    await this.refresh();
    uiStore.showToast(t("room.toast.invited"));
  },

  async kick(peerId: string) {
    if (!current) return;
    await removeRoomMember(current.id, peerId);
    await this.refresh();
    uiStore.showToast(t("room.toast.memberRemoved"));
  },

  // RC30/S9: owner flips is_approved — an "invited" member gets the room
  // key on the next rekey cycle only after approval.
  async approve(peerId: string) {
    if (!current) return;
    await approveRoomMember(current.id, peerId);
    await this.refresh();
    uiStore.showToast(t("room.toast.memberApproved"));
  },

  async leave() {
    if (!current) return;
    const id = current.id;
    await leaveRoom(id);
    rooms = rooms.filter(([rid]) => rid !== id);
    current = null;
    uiStore.resetNav("chats");
    uiStore.showToast(t("room.toast.left"));
  },

  async remove() {
    if (!current) return;
    const id = current.id;
    await deleteRoom(id);
    rooms = rooms.filter(([rid]) => rid !== id);
    current = null;
    uiStore.resetNav("chats");
    uiStore.showToast(t("room.toast.deleted"));
  },

  /** Wire backend events: refresh open settings on membership/meta
   * changes, drop the room locally when we are removed, and keep the
   * pending-invite list live. Call once at app start; returns the
   * unlisten cleanup. */
  async bindEvents(): Promise<UnlistenFn> {
    const unInvite = await onRoomInvite(async () => {
      await this.loadPendingInvites();
    });
    const unJoined = await onRoomJoined(async (p) => {
      // Key delivery completed — the room now exists locally.
      pendingInvites = pendingInvites.filter((i) => i.room_id !== p.room_id);
      await this.loadRooms();
      uiStore.showToast(t("room.toast.joined", { name: p.name ?? "" }).trim());
    });
    const unUpdated = await onRoomUpdated(async (p) => {
      if (p.kind === "removed") {
        rooms = rooms.filter(([id]) => id !== p.room_id);
        if (current && p.room_id === current.id) {
          current = null;
          uiStore.resetNav("chats");
          uiStore.showToast(t("room.toast.kicked"));
        }
        return;
      }
      if (current && p.room_id === current.id) {
        await this.refresh();
      }
    });
    return () => {
      unInvite();
      unJoined();
      unUpdated();
    };
  },
};
