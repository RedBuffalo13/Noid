import { describe, it, expect, vi, beforeEach } from "vitest";

const { isPermissionGrantedMock, requestPermissionMock, sendNotificationMock } = vi.hoisted(() => ({
  isPermissionGrantedMock: vi.fn(),
  requestPermissionMock: vi.fn(),
  sendNotificationMock: vi.fn(),
}));

vi.mock("@tauri-apps/plugin-notification", () => ({
  isPermissionGranted: isPermissionGrantedMock,
  requestPermission: requestPermissionMock,
  sendNotification: sendNotificationMock,
}));

import {
  initializeNotifications,
  showNotification,
  getNotificationSettings,
  saveNotificationSettings,
  checkNotificationPermission,
  notifyChatMessage,
  notifyContactRequest,
  notifyRoomMessage,
  notifyRoomInvite,
} from "./notifications";

describe("notifications", () => {
  beforeEach(() => {
    localStorage.clear();
    isPermissionGrantedMock.mockReset();
    requestPermissionMock.mockReset();
    sendNotificationMock.mockReset();
  });

  describe("initializeNotifications", () => {
    it("returns true when permission already granted", async () => {
      isPermissionGrantedMock.mockResolvedValue(true);
      const result = await initializeNotifications();
      expect(result).toBe(true);
      expect(requestPermissionMock).not.toHaveBeenCalled();
    });

    it("requests permission when not granted and returns true on 'granted'", async () => {
      isPermissionGrantedMock.mockResolvedValue(false);
      requestPermissionMock.mockResolvedValue("granted");
      const result = await initializeNotifications();
      expect(result).toBe(true);
    });

    it("returns false when permission denied", async () => {
      isPermissionGrantedMock.mockResolvedValue(false);
      requestPermissionMock.mockResolvedValue("denied");
      const result = await initializeNotifications();
      expect(result).toBe(false);
    });
  });

  describe("showNotification", () => {
    it("sends notification when permission granted", async () => {
      isPermissionGrantedMock.mockResolvedValue(true);
      await showNotification("Title", "Body");
      expect(sendNotificationMock).toHaveBeenCalledWith({ title: "Title", body: "Body" });
    });

    it("does not send notification when permission not granted", async () => {
      isPermissionGrantedMock.mockResolvedValue(false);
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      await showNotification("Title", "Body");
      expect(sendNotificationMock).not.toHaveBeenCalled();
      warnSpy.mockRestore();
    });

    it("passes icon option when provided", async () => {
      isPermissionGrantedMock.mockResolvedValue(true);
      await showNotification("Title", "Body", { icon: "icon.png" });
      expect(sendNotificationMock).toHaveBeenCalledWith({
        title: "Title",
        body: "Body",
        icon: "icon.png",
      });
    });
  });

  describe("getNotificationSettings", () => {
    it("returns defaults when localStorage is empty", () => {
      const s = getNotificationSettings();
      expect(s).toEqual({
        enabled: true,
        showPreview: true,
        sound: true,
        onlyMentions: false,
      });
    });

    it("returns stored settings", () => {
      const stored = { enabled: false, showPreview: false, sound: false, onlyMentions: true };
      localStorage.setItem("notificationSettings", JSON.stringify(stored));
      expect(getNotificationSettings()).toEqual(stored);
    });

    it("returns defaults on JSON parse error", () => {
      localStorage.setItem("notificationSettings", "invalid");
      const s = getNotificationSettings();
      expect(s.enabled).toBe(true);
    });
  });

  describe("saveNotificationSettings", () => {
    it("saves settings to localStorage", () => {
      const settings = { enabled: false, showPreview: true, sound: false, onlyMentions: true };
      saveNotificationSettings(settings);
      const stored = JSON.parse(localStorage.getItem("notificationSettings")!);
      expect(stored).toEqual(settings);
    });
  });

  describe("checkNotificationPermission", () => {
    it("returns isPermissionGranted result", async () => {
      isPermissionGrantedMock.mockResolvedValue(true);
      expect(await checkNotificationPermission()).toBe(true);
      isPermissionGrantedMock.mockResolvedValue(false);
      expect(await checkNotificationPermission()).toBe(false);
    });
  });

  describe("notifyChatMessage", () => {
    it("sends notification with preview by default", async () => {
      isPermissionGrantedMock.mockResolvedValue(true);
      await notifyChatMessage("peer1234567890", "hello");
      expect(sendNotificationMock).toHaveBeenCalledWith({
        title: "Message from peer1234...",
        body: "hello",
        sound: "default",
      });
    });

    it("hides body when showPreview is off", async () => {
      isPermissionGrantedMock.mockResolvedValue(true);
      saveNotificationSettings({ enabled: true, showPreview: false, sound: true, onlyMentions: false });
      await notifyChatMessage("peer1234567890", "secret text");
      expect(sendNotificationMock).toHaveBeenCalledWith({
        title: "Message from peer1234...",
        body: "New message",
        sound: "default",
      });
    });

    it("does not send when notifications disabled", async () => {
      isPermissionGrantedMock.mockResolvedValue(true);
      saveNotificationSettings({ enabled: false, showPreview: true, sound: true, onlyMentions: false });
      await notifyChatMessage("peer1", "hi");
      expect(sendNotificationMock).not.toHaveBeenCalled();
    });

    it("onlyMentions: skips messages without @username", async () => {
      isPermissionGrantedMock.mockResolvedValue(true);
      saveNotificationSettings({ enabled: true, showPreview: true, sound: true, onlyMentions: true });
      await notifyChatMessage("peer1", "hi there", "alice");
      expect(sendNotificationMock).not.toHaveBeenCalled();
      await notifyChatMessage("peer1", "hey @alice look", "alice");
      expect(sendNotificationMock).toHaveBeenCalledTimes(1);
    });
  });

  describe("notifyContactRequest", () => {
    it("sends contact request notification", async () => {
      isPermissionGrantedMock.mockResolvedValue(true);
      await notifyContactRequest("peerABCDEF12");
      expect(sendNotificationMock).toHaveBeenCalledWith({
        title: "New contact request",
        body: "From peerABCD...",
        sound: "default",
      });
    });
  });

  describe("notifyRoomMessage", () => {
    it("sends room message notification with sender prefix", async () => {
      isPermissionGrantedMock.mockResolvedValue(true);
      await notifyRoomMessage("roomid123456", "senderXYZ999", "room text");
      expect(sendNotificationMock).toHaveBeenCalledWith({
        title: "Room roomid12...",
        body: "senderXY...: room text",
        sound: "default",
      });
    });

    it("skips when onlyMentions is on", async () => {
      isPermissionGrantedMock.mockResolvedValue(true);
      saveNotificationSettings({ enabled: true, showPreview: true, sound: true, onlyMentions: true });
      await notifyRoomMessage("roomid123456", "senderXYZ999", "room text");
      expect(sendNotificationMock).not.toHaveBeenCalled();
    });
  });

  describe("notifyRoomInvite", () => {
    it("sends room invite notification", async () => {
      isPermissionGrantedMock.mockResolvedValue(true);
      await notifyRoomInvite("peerInviter99");
      expect(sendNotificationMock).toHaveBeenCalledWith({
        title: "Room invite",
        body: "peerInvi... invited you to a room",
        sound: "default",
      });
    });
  });
});
