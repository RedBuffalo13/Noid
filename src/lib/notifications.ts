
import { t } from './i18n/index.svelte';
import { 
  isPermissionGranted, 
  requestPermission, 
  sendNotification,
  type Options as TauriNotificationOptions
} from '@tauri-apps/plugin-notification';

export interface NotificationSettings {
  enabled: boolean;
  showPreview: boolean;
  sound: boolean;
  onlyMentions: boolean;
}

export async function initializeNotifications(): Promise<boolean> {
  let permission = await isPermissionGranted();
  
  if (!permission) {
    const result = await requestPermission();
    // requestPermission() returns a permission enum string, convert to boolean
    permission = result === 'granted';
  }
  
  return permission;
}

export async function showNotification(
  title: string,
  body: string,
  options?: {
    icon?: string;
    badge?: string;
    tag?: string;
    requireInteraction?: boolean;
    sound?: boolean;
  }
): Promise<void> {
  const granted = await isPermissionGranted();
  
  if (!granted) {
    console.warn('Notification permission not granted');
    return;
  }
  
  const notificationOptions: TauriNotificationOptions = {
    title,
    body,
  };
  
  if (options?.icon) {
    notificationOptions.icon = options.icon;
  }
  if (options?.sound) {
    // 'default' is honored on iOS/macOS; a no-op where unsupported.
    notificationOptions.sound = 'default';
  }
  
  sendNotification(notificationOptions);
}

export function getNotificationSettings(): NotificationSettings {
  try {
    const stored = localStorage.getItem('notificationSettings');
    return stored ? JSON.parse(stored) : {
      enabled: true,
      showPreview: true,
      sound: true,
      onlyMentions: false,
    };
  } catch {
    return {
      enabled: true,
      showPreview: true,
      sound: true,
      onlyMentions: false,
    };
  }
}

export function saveNotificationSettings(settings: NotificationSettings): void {
  localStorage.setItem('notificationSettings', JSON.stringify(settings));
}

export async function checkNotificationPermission(): Promise<boolean> {
  return await isPermissionGranted();
}

function shortId(peerId: string): string {
  return peerId.length > 8 ? `${peerId.slice(0, 8)}...` : peerId;
}

export async function notifyChatMessage(from: string, content: string, myUsername?: string): Promise<void> {
  const settings = getNotificationSettings();
  if (!settings.enabled) return;
  if (settings.onlyMentions && !(myUsername && content.includes(`@${myUsername}`))) return;
  await showNotification(
    t('notif.msg.from', { from: shortId(from) }),
    settings.showPreview ? content : t('notif.msg.new'),
    { sound: settings.sound }
  );
}

export async function notifyContactRequest(from: string): Promise<void> {
  const settings = getNotificationSettings();
  if (!settings.enabled) return;
  await showNotification(t('notif.request'), t('notif.request.from', { from: shortId(from) }), { sound: settings.sound });
}

export async function notifyContactAccepted(from: string): Promise<void> {
  const settings = getNotificationSettings();
  if (!settings.enabled) return;
  await showNotification(t('notif.accepted'), t('notif.accepted.by', { from: shortId(from) }), { sound: settings.sound });
}

export async function notifyRoomMessage(roomId: string, sender: string, content: string): Promise<void> {
  const settings = getNotificationSettings();
  if (!settings.enabled) return;
  if (settings.onlyMentions) return;
  await showNotification(
    t('notif.room', { id: shortId(roomId) }),
    settings.showPreview ? `${shortId(sender)}: ${content}` : t('notif.room.new'),
    { sound: settings.sound }
  );
}

export async function notifyRoomInvite(from: string): Promise<void> {
  const settings = getNotificationSettings();
  if (!settings.enabled) return;
  await showNotification(t('notif.invite'), t('notif.invite.from', { from: shortId(from) }), { sound: settings.sound });
}
