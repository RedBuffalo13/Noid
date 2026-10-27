import { t } from "$lib/i18n/index.svelte";
import { getContacts as svcGetContacts, getContactRequests as svcGetContactRequests, validatePeerId as svcValidatePeerId, sendContactRequest as svcSendContactRequest, acceptContactRequest as svcAcceptContactRequest, denyContactRequest as svcDenyContactRequest, removeContact as svcRemoveContact, getChatMessages as svcGetChatMessages } from "$lib/services";
import type { Chat } from "$lib/types";
import { SvelteSet } from "svelte/reactivity";
import { uiStore } from "./ui_store.svelte";
import { chatStore } from "./chat_store.svelte";

// Contacts are returned as tuples: [peerId, nickname, avatar]
type ContactRow = [string, string | null, string | null];
// Contact requests: [senderId, message, nickname, avatar]
type ContactRequestRow = [string, string, string | null, string | null];

let contacts = $state<ContactRow[]>([]);
let contactRequests = $state<ContactRequestRow[]>([]);
let chatList = $state<Chat[]>([]);
let requestPeerId = $state("");
let requestMessage = $state("Hello, I'd like to add you to my contacts.");
// FE-09: SvelteSet — plain Set mutations are invisible to $state
// reactivity; the online dot depends on this set live-updating.
let onlinePeers = new SvelteSet<string>();
// FE-18: coalescing — overlapping loadContacts calls used to run
// concurrently (3s + 5s timers + every peer event), last-write-wins.
// Now an in-flight call absorbs waiters into one follow-up pass.
let loadInFlight: Promise<void> | null = null;
let loadDirty = false;

export const contactStore = {
  get contacts() { return contacts; },
  get contactRequests() { return contactRequests; },
  get chatList() { return chatList; },
  get requestPeerId() { return requestPeerId; },
  set requestPeerId(val: string) { requestPeerId = val; },
  get requestMessage() { return requestMessage; },
  set requestMessage(val: string) { requestMessage = val; },
  get onlinePeers() { return onlinePeers; },

  setOnline(peerId: string) {
    // FE-09/FE-18: SvelteSet mutation IS the update — the template reads
    // `onlinePeers.has(chat.id)` live, no reload storm needed.
    onlinePeers.add(peerId);
  },

  setOffline(peerId: string) {
    onlinePeers.delete(peerId);
  },

  // IPC-02: node restart/wipe — no peer-disconnected events arrive, so the
  // stale "online" dots would linger forever without a bulk reset.
  clearOnline() {
    onlinePeers.clear();
  },

  async loadContacts() {
    if (loadInFlight) {
      loadDirty = true;
      return loadInFlight;
    }
    loadInFlight = (async () => {
      do {
        loadDirty = false;
        await this._loadContacts();
      } while (loadDirty);
      loadInFlight = null;
    })();
    return loadInFlight;
  },

  async _loadContacts() {
    try {
      contacts = (await svcGetContacts()) as ContactRow[];
      contactRequests = (await svcGetContactRequests()) as ContactRequestRow[];

      const loadedChats = await Promise.all(
        contacts.map(async (contact) => {
          let lastMsg = "No messages yet";
          let lastMsgTime: number | undefined;
          try {
            const chatMessages = (await svcGetChatMessages(contact[0])) as any;
            if (chatMessages.length > 0) {
              const last = chatMessages[chatMessages.length - 1];
              // FE-11: truncate — a whole message body as a list subtitle is
              // unreadable; the real text lives in chat-view.
              lastMsg = last[2].length > 60 ? last[2].slice(0, 60) + "…" : last[2];
              lastMsgTime = new Date(last[3]).getTime() || undefined;
            }
          } catch (e) {}

          return {
            id: contact[0],
            name: contact[1] || "Unknown",
            lastMsg,
            lastMsgTime,
            unread: chatStore.getUnread(contact[0]),
            avatar: contact[2] || undefined,
            isOnline: onlinePeers.has(contact[0]),
          } as Chat;
        }),
      );
      chatList = loadedChats;
    } catch (e) {
      console.error("Failed to load contacts", e);
    }
  },

  async sendRequest() {
    if (!requestPeerId.trim()) {
      uiStore.showToast(t("contacts.toast.needPeerId"));
      return;
    }
    try {
      const isValid = await svcValidatePeerId(requestPeerId);
      if (!isValid) {
        uiStore.showToast(t("contacts.toast.badPeerId"));
        return;
      }
      await svcSendContactRequest(requestPeerId, requestMessage);
      uiStore.showToast(t("contacts.toast.requestSent"));
      uiStore.subPage = "contacts";
      requestPeerId = "";
    } catch (e) {
      uiStore.showToast(t("contacts.toast.error", { e: String(e) }));
    }
  },

  async acceptRequest(peerId: string) {
    try {
      const isValid = await svcValidatePeerId(peerId);
      if (!isValid) {
        uiStore.showToast(t("contacts.toast.badPeerId"));
        return;
      }
      await svcAcceptContactRequest(peerId);
      uiStore.showToast(t("contacts.toast.requestAccepted"));
      await this.loadContacts();
    } catch (e) {
      uiStore.showToast(t("contacts.toast.error", { e: String(e) }));
    }
  },

  async denyRequest(peerId: string) {
    try {
      const isValid = await svcValidatePeerId(peerId);
      if (!isValid) {
        uiStore.showToast(t("contacts.toast.badPeerId"));
        return;
      }
      await svcDenyContactRequest(peerId);
      uiStore.showToast(t("contacts.toast.requestDenied"));
      await this.loadContacts();
    } catch (e) {
      uiStore.showToast(t("contacts.toast.error", { e: String(e) }));
    }
  },

  async deleteContact(peerId: string) {
    try {
      await svcRemoveContact(peerId);
      uiStore.showToast(t("contacts.toast.deleted"));
      await this.loadContacts();
    } catch (e) {
      uiStore.showToast(t("contacts.toast.error", { e: String(e) }));
    }
  }
};
