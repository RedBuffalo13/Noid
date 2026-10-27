import { open } from "@tauri-apps/plugin-dialog";
import { readFile } from "@tauri-apps/plugin-fs";

/**
 * Pick an image file, center-crop it square and resize to `size` px,
 * returning a JPEG data-URL (bounded size — safe to store/send as an
 * avatar). Returns null when the dialog is cancelled or the image is
 * undecodable.
 */
export async function pickImageDataUrl(size = 320): Promise<string | null> {
  const selected = await open({
    filters: [{ name: "Images", extensions: ["png", "jpg", "jpeg", "webp"] }],
    multiple: false,
  });
  if (!selected || typeof selected !== "string") return null;

  const bytes = await readFile(selected);
  const url = URL.createObjectURL(new Blob([bytes]));
  try {
    const img = new Image();
    img.src = url;
    await new Promise((resolve, reject) => {
      img.onload = resolve;
      img.onerror = reject;
    });

    const canvas = document.createElement("canvas");
    canvas.width = size;
    canvas.height = size;
    const ctx = canvas.getContext("2d");
    if (!ctx) return null;

    const minDim = Math.min(img.width, img.height);
    const sx = (img.width - minDim) / 2;
    const sy = (img.height - minDim) / 2;
    ctx.drawImage(img, sx, sy, minDim, minDim, 0, 0, size, size);
    return canvas.toDataURL("image/jpeg", 0.7);
  } finally {
    URL.revokeObjectURL(url);
  }
}
