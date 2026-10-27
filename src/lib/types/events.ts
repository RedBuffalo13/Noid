// Phase C.2: Typed event payloads for Tauri event listeners

export interface ChatMsgEvent {
  from: string;
  data: {
    content: string;
    id: string;
    sender: string;
    timestamp?: string;
  };
}

export interface MessageReadEvent {
  from: string;
  message_id: string;
}

export interface MessageFailedEvent {
  to: string;
  error: string;
  /** TI-3: the specific failed message — absent only on legacy peers. */
  message_id?: string;
}

export interface MessageDeliveredEvent {
  peer_id: string;
  message_id: string;
}

export interface P2PEventPayload {
  message: string;
}

export interface PeerConnectedEvent {
  peerId: string;
}

export interface PeerOnlineEvent {
  peerId: string;
}

export interface PeerDisconnectedEvent {
  peerId: string;
}

export interface PendingMessagesSentEvent {
  peerId: string;
}

export interface UsernameAvailabilityEvent {
  username: string;
  available: boolean;
}

export interface UserLookupResultEvent {
  username: string;
  record: {
    peerId: string;
    nickname: string;
    avatar: string | null;
    shortId: string;
  } | null;
}

export interface MyIdEvent {
  peerId: string;
}

// Unlistener cleanup function type
export type Unlistener = () => void;
