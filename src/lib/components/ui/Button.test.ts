import { describe, it, expect, vi } from "vitest";
import { render, fireEvent } from "@testing-library/svelte";
import PinEntry from "../auth/PinEntry.svelte";

// PinEntry is Button's live consumer — testing through it covers the
// Button rendering contract AND the PIN-keypad behaviour (FE-13/FE-22).
describe("PinEntry (Button via numpad)", () => {
  it("renders 12 keypad buttons including backspace and OK", () => {
    const { container } = render(PinEntry);
    const buttons = container.querySelectorAll(".numpad button");
    expect(buttons.length).toBe(12);
    expect(container.querySelector('[aria-label="Backspace"]')).toBeTruthy();
  });

  it("emits digits through oninput and submits via onsubmit", async () => {
    const oninput = vi.fn();
    const onsubmit = vi.fn();
    const { getByText } = render(PinEntry, { props: { pin: "12", oninput, onsubmit } });
    await fireEvent.click(getByText("5"));
    expect(oninput).toHaveBeenCalledWith("125");
    await fireEvent.click(getByText("OK"));
    expect(onsubmit).toHaveBeenCalledWith("12");
  });

  it("backspace removes the last digit", async () => {
    const oninput = vi.fn();
    const { getByLabelText } = render(PinEntry, { props: { pin: "123", oninput } });
    await fireEvent.click(getByLabelText("Backspace"));
    expect(oninput).toHaveBeenCalledWith("12");
  });

  it("never writes the PIN to the console (FE-22)", async () => {
    const spy = vi.spyOn(console, "log");
    const { getByText } = render(PinEntry, { props: { pin: "1" } });
    await fireEvent.click(getByText("2"));
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });
});
