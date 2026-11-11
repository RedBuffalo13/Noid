import { t } from "#lib/i18n/index.svelte";
import { getChatMessages as svcGetChatMessages, getNewMessagesSince as svcGetNewMessagesSince, getAllMissedMessages as svcGetAllMissedMessages, sendChatMessage as svcSendChatMessage, sendTypingIndicator as svcSendTypingIndicator, getPendingMessageIds as svcGetPendingMessageIds, deleteChat as svcDeleteChat, setUnreadCount as svcSetUnreadCount, getUnreadCounts as svcGetUnreadCounts } from "#lib/services";
import { tick } from "svelte";
import type { Message } from "#lib/types";
import { SvelteMap } from "svelte/reactivity";
import { uiStore } from "./ui_store.svelte";

let messages = $state<Message[]>([]);
let currentPeer = $state("");
let inputMsg = $state("");
let myId = $state("");
// FE-09: SvelteMap — badge reads getUnread() live; plain Map mutations
// never re-rendered and needed a loadContacts poll to surface.
let unreadCount = new SvelteMap<string, number>();
// FE-A04: delivery ACKs can arrive before send_chat_message resolves and
// the optimistic row swaps temp→real id. Buffer them per peer and apply on
// the swap instead of dropping the receipt.
const pendingDelivery = new Map<string, Set<string>>();
// OPT-F06: peers with a missed-message sync already in flight.
const syncInflight = new Set<string>();
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
  // FE-A01: KillPin wipe — drop every plaintext remnant immediately:
  // history, open chat, draft, unread counters and buffered ACKs.
  revokeSession() {
    messages = [];
    currentPeer = "";
    inputMsg = "";
    unreadCount.clear();
    pendingDelivery.clear();
  },
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
      const ackedEarly = pendingDelivery.get(currentPeer)?.has(msgId) ?? false;
      pendingDelivery.get(currentPeer)?.delete(msgId);
      markOptimistic({
        id: msgId,
        status: ackedEarly ? ("delivered" as const) : ("sent" as const),
        delivered: ackedEarly,
      });
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

  // NET-A04: mailbox-stored ≠ delivered — the envelope reached the peer's
  // mailbox, not the peer. Distinct status so ✓✓ stays honest.
  markMessageQueued(peerId: string, messageId: string) {
    if (peerId !== currentPeer) return;
    messages = messages.map(msg => {
      if (msg.id === messageId && msg.from === "Me") {
        return { ...msg, status: "queued" as const };
      }
      return msg;
    });
  },

  // TI-4: precise delivery — mark only the acked message, not the whole
  // peer's history. Used by `message-delivered` (direct peer ack);
  // `mailbox-stored` now routes to markMessageQueued.
  markMessageDelivered(peerId: string, messageId: string) {
    // Buffer first — the row may still carry its temp id, or the chat may
    // not be open; drop only after the swap had its chance.
    let matched = false;
    if (peerId === currentPeer) {
      messages = messages.map(msg => {
        if (msg.id === messageId && msg.from === "Me") {
          matched = true;
          return { ...msg, status: "delivered" as const, delivered: true };
        }
        return msg;
      });
    }
    if (!matched) {
      const set = pendingDelivery.get(peerId) ?? new Set<string>();
      set.add(messageId);
      pendingDelivery.set(peerId, set);
    }
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
    // OPT-F06: `peer-connected` and `peer-online` both fire this on one
    // reconnect — coalesce concurrent triggers into a single sync owner.
    if (syncInflight.has(peerId)) return;
    syncInflight.add(peerId);
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
    } finally {
      syncInflight.delete(peerId);
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
        const dbIds = new Set(chatMessages.map(([id]: [string, string, string, string]) => id));
        // OPT-F04: wholesale replace dropped in-flight optimistic bubbles
        // (temp id, not yet in DB) — the row vanished mid-send then popped
        // back. Merge: keep local rows the DB doesn't know yet, sort by ts.
        const inFlight = messages.filter(
          (m) => m.from === "Me" && !!m.id && !dbIds.has(m.id) &&
            (m.status === "sending" || m.id.startsWith("optimistic-"))
        );
        const merged = chatMessages.map(([id, senderId, content, timestamp]: [string, string, string, string]) => ({
          id,
          from: senderId === myId ? "Me" : senderId,
          content,
          type: (senderId === myId ? "sent" : "received") as "sent" | "received",
          timestamp: new Date(timestamp).getTime(),
          delivered: !pendingIds.has(id),
          status: pendingIds.has(id) ? "sent" as const : undefined,
          seen: false
        }));
        messages = trimMessages(
          [...merged, ...inFlight].sort((a, b) => a.timestamp - b.timestamp)
        );
        autoScroll();
      }
    } catch (e) {}
  },

  // Phase D.1: Unread count management — FE-A08: every change is
  // persisted; a restart reloads the live set instead of zeroing it.
  incrementUnread(peerId: string) {
    const next = (unreadCount.get(peerId) || 0) + 1;
    unreadCount.set(peerId, next);
    svcSetUnreadCount(peerId, next).catch(() => {});
  },

  clearUnread(peerId: string) {
    unreadCount.set(peerId, 0);
    svcSetUnreadCount(peerId, 0).catch(() => {});
  },

  async loadUnreadCounts() {
    try {
      for (const [peerId, count] of await svcGetUnreadCounts()) {
        unreadCount.set(peerId, count);
      }
    } catch { /* counts stay in-memory only — non-fatal */ }
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
