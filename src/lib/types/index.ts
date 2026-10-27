export interface Message {
  id?: string;          // Phase 4.1: message ID for read receipts
  from: string;
  content: string;
  type: "sent" | "received";
  timestamp: number;
  delivered?: boolean;
  seen?: boolean;
  status?: 'sending' | 'sent' | 'delivered' | 'failed';
}

export interface Chat {
  id: string;
  name: string;
  lastMsg: string;
  /** FE-11: epoch ms of the last message — drives `chat-time`. */
  lastMsgTime?: number;
  unread: number;
  avatar?: string;
  isOnline?: boolean;
}

export interface Contact {
  peerId: string;
  nickname: string | null;
  avatar: string | null;
  isBlocked: boolean;
}

export interface ContactRequest {
  senderId: string;
  message: string;
  nickname: string | null;
  avatar: string | null;
}

export type Screen = 'checking' | 'setup' | 'pin-entry' | 'main';
export type SubPage = 'chats' | 'settings' | 'contacts' | 'chat-view' | 'received-requests' | 'send-request';

export interface UserRecord {
  peerId: string;
  nickname: string;
  avatar: string | null;
  shortId: string;
}

export interface UserSearchResult {
  record: UserRecord;
  source: 'dht' | 'peer';
  isOnline: boolean;
}
