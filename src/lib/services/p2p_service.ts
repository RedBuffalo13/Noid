import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export interface ChatMsgPayload {
  from: string;
  data: any;
}

export interface MessageReadPayload {
  from: string;
  message_id: string;
}

export async function onChatMsg(cb: (payload: ChatMsgPayload) => void): Promise<UnlistenFn> {
  return listen<ChatMsgPayload>("chat-msg", (e) => cb(e.payload));
}

export async function onPeerConnected(cb: (peer: string) => void): Promise<UnlistenFn> {
  return listen<string>("peer-connected", (e) => cb(e.payload));
}

export async function onPeerDisconnected(cb: (peer: string) => void): Promise<UnlistenFn> {
  return listen<string>("peer-disconnected", (e) => cb(e.payload));
}

export async function onPeerOnline(cb: (peer: string) => void): Promise<UnlistenFn> {
  return listen<string>("peer-online", (e) => cb(e.payload));
}

export interface MessageFailedPayload {
  to: string;
  error: string;
}

export async function onMessageFailed(cb: (payload: MessageFailedPayload) => void): Promise<UnlistenFn> {
  return listen<MessageFailedPayload>("message-failed", (e) => cb(e.payload));
}

export async function onPendingMessagesSent(cb: (peer: string) => void): Promise<UnlistenFn> {
  return listen<string>("pending-messages-sent", (e) => cb(e.payload));
}

export async function onMessageRead(cb: (payload: MessageReadPayload) => void): Promise<UnlistenFn> {
  return listen<MessageReadPayload>("message-read", (e) => cb(e.payload));
}

export async function onTypingIndicator(cb: (peer: string) => void): Promise<UnlistenFn> {
  return listen<string>("typing-indicator", (e) => cb(e.payload));
}

export async function onP2PRequest(cb: (payload: any) => void): Promise<UnlistenFn> {
  return listen("p2p-request", (e) => cb(e.payload));
}
