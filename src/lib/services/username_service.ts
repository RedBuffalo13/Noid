import { invoke } from "@tauri-apps/api/core";

export async function setUsername(username: string): Promise<void> {
  await invoke("set_username", { username });
}

export async function checkUsername(username: string): Promise<void> {
  await invoke("check_username", { username });
}

export async function lookupUser(username: string): Promise<void> {
  await invoke("lookup_user", { username });
}

export async function lookupByPeerId(peerId: string): Promise<boolean> {
  return await invoke("lookup_by_peer_id", { peerId });
}

export async function getUsername(): Promise<string | null> {
  return await invoke("get_username");
}
