// Minimal dependency-free i18n. `en` is the default locale and the source of
// truth for keys; `ru` is required to mirror it (type-checked).
import { en, type MessageKey } from "./en";
import { ru } from "./ru";

export type Locale = "en" | "ru";

const dicts: Record<Locale, Record<MessageKey, string>> = { en, ru };
const STORAGE_KEY = "noid.locale";

let locale = $state<Locale>(loadLocale());
let dict = $derived(dicts[locale]);

function loadLocale(): Locale {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored === "ru" ? "ru" : "en";
  } catch {
    return "en";
  }
}

export const i18n = {
  get locale() { return locale; },
  setLocale(l: Locale) {
    locale = l;
    try { localStorage.setItem(STORAGE_KEY, l); } catch { /* private mode */ }
  },
};

/**
 * Translate a key with optional `{name}` interpolation.
 * Falls back to English for a missing RU string.
 */
export function t(key: MessageKey, params?: Record<string, string | number>): string {
  let s = dict[key] ?? en[key] ?? key;
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      s = s.replaceAll(`{${k}}`, String(v));
    }
  }
  return s;
}
