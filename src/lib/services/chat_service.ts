import { invoke } from "@tauri-apps/api/core";

export interface ChatMessage {
  id: string;
  senderId: string;
  content: string;
  timestamp: string;
}

export async function getChatMessages(peerId: string): Promise<[string, string, string, string][]> {
  return invoke<[string, string, string, string][]>("get_chat_messages", { peerId });
}

export async function getNewMessagesSince(peerId: string, sinceTime: string): Promise<[string, string, string, string][]> {
  return invoke<[string, string, string, string][]>("get_new_messages_since", { peerId, sinceTime });
}

export async function getAllMissedMessages(): Promise<Record<string, [string, string, string, string][]>> {
  return invoke<Record<string, [string, string, string, string][]>>("get_all_missed_messages");
}

/** Returns the backend-generated message id — attach it to the optimistic
 * bubble so delivery/read events match by id (FE-23). */
export async function sendChatMessage(peerId: string, content: string): Promise<string> {
  return invoke<string>("send_chat_message", { peerId, content });
}

export async function sendReadReceipt(peerId: string, messageId: string): Promise<void> {
  return invoke("send_read_receipt", { peerId, messageId });
}

/** TI-4: ids of outbound messages still queued for delivery — the chat
 *  view renders these as pending instead of a fabricated "delivered". */
export async function getPendingMessageIds(peerId: string): Promise<string[]> {
  return invoke("get_pending_message_ids", { peerId });
}

export async function sendTypingIndicator(peerId: string): Promise<void> {
  return invoke("send_typing_indicator", { peerId });
}

/** Deletes the whole direct-chat history with a peer (and its undelivered
 *  outbox). The contact itself is kept — use `removeContact` for that. */
export async function deleteChat(peerId: string): Promise<void> {
  return invoke("delete_chat", { peerId });
}
