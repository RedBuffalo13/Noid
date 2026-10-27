import { invoke } from "@tauri-apps/api/core";

export interface SharedFolder {
  id: string;
  path: string;
  isPublic: boolean;
  hasPassword: boolean;
}

export async function updateFolderPath(id: string, newPath: string): Promise<void> {
  await invoke("update_folder_path", { id, newPath });
}

export async function updateFolderVisibility(id: string, isPublic: boolean): Promise<void> {
  await invoke("update_folder_visibility", { id, isPublic });
}

export async function updateFolderPassword(id: string, password: string): Promise<void> {
  await invoke("update_folder_password", { id, password });
}

export async function deleteSharedFolder(id: string): Promise<void> {
  await invoke("delete_shared_folder", { id });
}

export async function searchSharedFolders(query: string): Promise<[string, string, boolean, string | null][]> {
  return await invoke("search_shared_folders", { query });
}
