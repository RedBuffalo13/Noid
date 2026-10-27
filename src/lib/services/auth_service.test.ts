import { describe, it, expect, vi, beforeEach } from "vitest";
import { invokeMock } from "../../test-setup";
import { login, setupPins, isFirstRun } from "./auth_service";

describe("auth_service", () => {
  beforeEach(() => {
    invokeMock.mockReset();
  });

  it("login calls invoke('login', {pin})", async () => {
    invokeMock.mockResolvedValue({ success: true, message: "ok", kind: "ok" });
    const result = await login("12345678");
    expect(invokeMock).toHaveBeenCalledWith("login", { pin: "12345678" });
    expect(result.success).toBe(true);
  });

  it("setupPins calls invoke('setup_pins', {truePin, killPin})", async () => {
    invokeMock.mockResolvedValue({ success: true, message: "ok", kind: "ok" });
    await setupPins("truepin123", "killpin123");
    expect(invokeMock).toHaveBeenCalledWith("setup_pins", {
      truePin: "truepin123",
      killPin: "killpin123",
    });
  });

  it("isFirstRun calls invoke('is_first_run')", async () => {
    invokeMock.mockResolvedValue(true);
    const result = await isFirstRun();
    expect(invokeMock).toHaveBeenCalledWith("is_first_run");
    expect(result).toBe(true);
  });
});
