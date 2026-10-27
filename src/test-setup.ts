// Test setup file — mocks for Tauri APIs and browser APIs
import "@testing-library/jest-dom/vitest";
import { vi, beforeEach } from "vitest";

// --- Mock @tauri-apps/api/core invoke ---
// Per-test override: import { mockInvoke } from "$lib/test/mocks"; mockInvoke.mockResolvedValue(...)
const invokeMock = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({
  invoke: invokeMock,
}));
export { invokeMock };

// --- Mock @tauri-apps/plugin-dialog ---
vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: vi.fn().mockResolvedValue(null),
}));

// --- Mock @tauri-apps/plugin-fs ---
vi.mock("@tauri-apps/plugin-fs", () => ({
  readFile: vi.fn().mockResolvedValue(new Uint8Array()),
  writeFile: vi.fn().mockResolvedValue(undefined),
}));

// --- Mock @tauri-apps/plugin-clipboard-manager ---
vi.mock("@tauri-apps/plugin-clipboard-manager", () => ({
  writeText: vi.fn().mockResolvedValue(undefined),
  readText: vi.fn().mockResolvedValue(""),
}));

// --- Mock @tauri-apps/plugin-notification ---
vi.mock("@tauri-apps/plugin-notification", () => ({
  isPermissionGranted: vi.fn().mockResolvedValue(true),
  requestPermission: vi.fn().mockResolvedValue("granted"),
  sendNotification: vi.fn(),
}));

// --- Mock window.matchMedia (jsdom не предоставляет) ---
if (!window.matchMedia) {
  window.matchMedia = (query: string): MediaQueryList => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  });
}

// --- Mock URL.createObjectURL / revokeObjectURL ---
if (!URL.createObjectURL) {
  URL.createObjectURL = vi.fn().mockReturnValue("blob:mock");
}
if (!URL.revokeObjectURL) {
  URL.revokeObjectURL = vi.fn();
}

// --- Очистка localStorage между тестами ---
beforeEach(() => {
  localStorage.clear();
});
