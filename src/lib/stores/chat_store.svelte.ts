import { t } from "$lib/i18n/index.svelte";
import { getChatMessages as svcGetChatMessages, getNewMessagesSince as svcGetNewMessagesSince, getAllMissedMessages as svcGetAllMissedMessages, sendChatMessage as svcSendChatMessage, sendTypingIndicator as svcSendTypingIndicator, getPendingMessageIds as svcGetPendingMessageIds, deleteChat as svcDeleteChat } from "$lib/services";
import { tick } from "svelte";
import type { Message } from "$lib/types";
import { SvelteMap } from "svelte/reactivity";
import { uiStore } from "./ui_store.svelte";

let messages = $state<Message[]>([]);
let currentPeer = $state("");
let inputMsg = $state("");
let myId = $state("");
// FE-09: SvelteMap — badge reads getUnread() live; plain Map mutations
// never re-rendered and needed a loadContacts poll to surface.
let unreadCount = new SvelteMap<string, number>();
let lastTypingSent = 0;
// FE-30: incoming typing events live here — rendered inside the chat view,
// not as a toast that spams on every keystroke-burst.
let typingFrom = $state("");
let typingTimer: ReturnType<typeof setTimeout> | null = null;

// FE-19: only snap to bottom when the user is already near it — a
// refresh or incoming message must not yank them out of history.
async function autoScroll() {
  await tick();
  const scroller = document.querySelector(".message-list");
  if (!scroller) return;
  const nearBottom =
    scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight < 120;
  if (nearBottom) scroller.scrollTop = scroller.scrollHeight;
}

// FE-20: render cap — the DB already bounds history reads; this bounds
// the live array so an open session can't grow without limit.
const MAX_RENDERED = 1000;
function trimMessages(list: Message[]): Message[] {
  return list.length > MAX_RENDERED ? list.slice(-MAX_RENDERED) : list;
}

export const chatStore = {
  get messages() { return messages; },
  set messages(val: Message[]) { messages = val; },
  get currentPeer() { return currentPeer; },
  set currentPeer(val: string) { currentPeer = val; },
  get inputMsg() { return inputMsg; },
  set inputMsg(val: string) { inputMsg = val; },
  get myId() { return myId; },
  set myId(val: string) { myId = val; },
  get unreadCount() { return unreadCount; },
  get typingFrom() { return typingFrom; },

  /** FE-30: mark `peerId` as typing; auto-clears after 4s (indicators are
   * one-shots on the wire, re-sent by the peer while typing). */
  setTyping(peerId: string) {
    typingFrom = peerId;
    if (typingTimer) clearTimeout(typingTimer);
    typingTimer = setTimeout(() => { typingFrom = ""; typingTimer = null; }, 4000);
  },

  async loadMessages(peerId: string) {
    try {
      const chatMessages = (await svcGetChatMessages(peerId)) as any;
      // TI-4: outbound rows still in the pending outbox are NOT delivered —
      // mark them instead of the blanket `delivered: true` below.
      const pendingIds = new Set(await svcGetPendingMessageIds(peerId).catch(() => []));
      // FE-01: the user may have switched chats during the awaits — a
      // stale peer's history must not clobber the now-open conversation.
      if (peerId !== currentPeer) return;
      messages = trimMessages(chatMessages.map(([id, senderId, content, timestamp]: [string, string, string, string]) => ({
        id,
        from: senderId === myId ? "Me" : senderId,
        content,
        type: (senderId === myId ? "sent" : "received") as "sent" | "received",
        timestamp: new Date(timestamp).getTime(),
        delivered: !pendingIds.has(id),
        status: pendingIds.has(id) ? "sent" as const : undefined,
        seen: false
      })));
      // Clear unread count for this peer
      unreadCount.set(peerId, 0);
      autoScroll();
    } catch (e) {
      console.error("Failed to load chat messages:", e);
      messages = [];
    }
  },

  async sendMessage() {
    if (!inputMsg.trim()) return;
    const content = inputMsg;
    inputMsg = "";

    // FE-23: optimistic bubble gets a temp id — $state proxies break ===
    // identity, so the update keys on the temp id and swaps in the real
    // one once send_chat_message returns it.
    const tempId = `optimistic-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const newMessage: Message = {
      id: tempId,
      from: "Me",
      content,
      type: "sent",
      timestamp: Date.now(),
      status: "sending",
      delivered: false,
      seen: false
    };

    messages = trimMessages([...messages, newMessage]);
    autoScroll();

    const markOptimistic = (patch: Partial<Message>) => {
      messages = messages.map((m) => (m.id === tempId ? { ...m, ...patch } : m));
    };

    try {
      const msgId = await svcSendChatMessage(currentPeer, content);
      markOptimistic({ id: msgId, status: "sent" as const });
    } catch (e) {
      console.error("Failed to send:", e);
      markOptimistic({ status: "failed" as const, delivered: false });
      uiStore.showToast(t("chat.toast.sendFailed"));
    }
  },

  // TI-26: typing indicator — the listener existed but nothing sent.
  // Throttled to one wire message per 3s of typing.
  notifyTyping() {
    if (!currentPeer || !inputMsg.trim()) return;
    const now = Date.now();
    if (now - lastTypingSent < 3000) return;
    lastTypingSent = now;
    svcSendTypingIndicator(currentPeer).catch(() => {});
  },

  appendMessage(msg: Message) {
    // Idempotent: room messages can arrive twice (gossipsub + RoomChat
    // fan-out copy) — the backend dedups by msg_id, this is the UI guard.
    if (msg.id && messages.some((m) => m.id === msg.id)) return;
    messages = trimMessages([...messages, msg]);
    autoScroll();
  },

  markDeliveredToCurrentPeer() {
    messages = messages.map(msg => {
      if (msg.from === "Me" && msg.status === "sent") {
        return { ...msg, status: "delivered" as const, delivered: true };
      }
      return msg;
    });
  },

  // TI-3/TI-5: the event now carries the failed message_id — mark that
  // row only; a blast radius of "every sent message" misreported status.
  markFailed(failedPeerId: string, messageId?: string) {
    messages = messages.map(msg => {
      if (msg.from === "Me" && failedPeerId === currentPeer
          && (!messageId || msg.id === messageId)) {
        return { ...msg, delivered: false, status: "failed" as const };
      }
      return msg;
    });
  },

  // TI-4: precise delivery — mark only the acked message, not the whole
  // peer's history. Used by `message-delivered` (direct ack) and
  // `mailbox-stored` (queued for offline delivery).
  markMessageDelivered(peerId: string, messageId: string) {
    if (peerId !== currentPeer) return;
    messages = messages.map(msg => {
      if (msg.id === messageId && msg.from === "Me") {
        return { ...msg, status: "delivered" as const, delivered: true };
      }
      return msg;
    });
  },

  markPendingSent(peerId: string) {
    messages = messages.map(msg => {
      if (msg.from === "Me" && peerId === currentPeer && !msg.delivered) {
        return { ...msg, delivered: true };
      }
      return msg;
    });
  },

  async checkMissedMessagesFromPeer(peerId: string) {
    if (currentPeer !== peerId) return;
    try {
      const lastMessageTime = messages.length > 0
        ? new Date(Math.max(...messages.map(m => m.timestamp))).toISOString()
        : new Date(0).toISOString();

      const newMessages = await svcGetNewMessagesSince(peerId, lastMessageTime) as any;

      if (newMessages.length > 0) {
        // FE-01: recheck after the await + drop ids already rendered by
        // the live `chat-msg` listener (event + poll raced).
        if (currentPeer !== peerId) return;
        const have = new Set(messages.map(m => m.id));
        const fresh = newMessages.filter(([id]: [string, ...unknown[]]) => !have.has(id));
        if (fresh.length === 0) return;
        const newMessageObjects: Message[] = fresh.map(([id, senderId, content, timestamp]: [string, string, string, string]) => ({
          id,
          from: senderId === myId ? "Me" : senderId,
          content,
          type: (senderId === myId ? "sent" : "received") as "sent" | "received",
          timestamp: new Date(timestamp).getTime(),
          delivered: true,
          seen: false
        }));
        messages = trimMessages([...messages, ...newMessageObjects].sort((a, b) => a.timestamp - b.timestamp));
        autoScroll();
      }
    } catch (e) {
      console.error("Error fetching new messages:", e);
    }
  },

  async checkAllMissedMessages() {
    try {
      const allMissed = await svcGetAllMissedMessages() as any;
      const peer = currentPeer;
      // IPC-04: missed messages exist for EVERY chat — when no chat is
      // open (fresh login) the old code skipped the map entirely and
      // unreadCount stayed 0 for all peers with new messages.
      for (const [peerId, msgs] of Object.entries(allMissed) as [string, [string, string, string, string][]][]) {
        if (peerId === peer) continue; // open chat is appended below
        const incoming = msgs.filter(([, senderId]) => senderId === peerId).length;
        if (incoming > 0) {
          unreadCount.set(peerId, incoming);
        }
      }
      if (peer && allMissed[peer]) {
        const have = new Set(messages.map(m => m.id));
        const fresh = allMissed[peer].filter(([id]: [string, ...unknown[]]) => !have.has(id));
        if (fresh.length === 0 || currentPeer !== peer) return;
        const newMessages: Message[] = fresh.map(([id, senderId, content, timestamp]: [string, string, string, string]) => ({
          id,
          from: senderId === myId ? "Me" : senderId,
          content,
          type: (senderId === myId ? "sent" : "received") as "sent" | "received",
          timestamp: new Date(timestamp).getTime(),
          delivered: true,
          seen: false
        }));
        messages = trimMessages([...messages, ...newMessages].sort((a, b) => a.timestamp - b.timestamp));
        autoScroll();
      }
    } catch (e) {
      console.error("Error fetching missed messages:", e);
    }
  },

  async refreshCurrentChat() {
    const peer = currentPeer;
    if (!peer) return;
    try {
      const chatMessages = (await svcGetChatMessages(peer)) as any;
      if (peer !== currentPeer) return; // FE-01
      if (chatMessages.length !== messages.length) {
        const pendingIds = new Set(await svcGetPendingMessageIds(peer).catch(() => []));
        if (peer !== currentPeer) return; // FE-01
        messages = trimMessages(chatMessages.map(([id, senderId, content, timestamp]: [string, string, string, string]) => ({
          id,
          from: senderId === myId ? "Me" : senderId,
          content,
          type: (senderId === myId ? "sent" : "received") as "sent" | "received",
          timestamp: new Date(timestamp).getTime(),
          delivered: !pendingIds.has(id),
          status: pendingIds.has(id) ? "sent" as const : undefined,
          seen: false
        })));
        autoScroll();
      }
    } catch (e) {}
  },

  // Phase D.1: Unread count management
  incrementUnread(peerId: string) {
    const current = unreadCount.get(peerId) || 0;
    unreadCount.set(peerId, current + 1);
  },

  clearUnread(peerId: string) {
    unreadCount.set(peerId, 0);
  },

  getUnread(peerId: string): number {
    return unreadCount.get(peerId) || 0;
  },

  async deleteChat(peerId: string) {
    await svcDeleteChat(peerId);
    if (currentPeer === peerId) messages = [];
    unreadCount.delete(peerId);
  }
};
