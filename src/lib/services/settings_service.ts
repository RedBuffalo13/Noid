import { invoke } from "@tauri-apps/api/core";

export async function getLastSyncTime(): Promise<string> {
  return invoke<string>("get_last_sync_time");
}

export async function registerFolder(path: string): Promise<void> {
  return invoke("register_folder", { path });
}

export async function getSharedFolders(): Promise<[string, string, boolean][]> {
  return invoke<[string, string, boolean][]>("get_shared_folders");
}

export async function approveRoomMember(roomId: string, peerId: string): Promise<void> {
  return invoke("approve_room_member", { roomId, peerId });
}
