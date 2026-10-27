import { invoke } from "@tauri-apps/api/core";

export async function sendFileOffer(peerId: string, fileName: string, fileSize: number): Promise<string> {
  return invoke<string>("send_file_offer", { peerId, fileName, fileSize });
}

export async function sendFileChunk(peerId: string, offerId: string, chunkIndex: number, totalChunks: number, data: number[]): Promise<void> {
  return invoke("send_file_chunk", { peerId, offerId, chunkIndex, totalChunks, data });
}

const CHUNK_SIZE = 16384;

export async function sendFile(peerId: string, file: File): Promise<void> {
  const offerId = await sendFileOffer(peerId, file.name, file.size);
  const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
  for (let i = 0; i < totalChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, file.size);
    const slice = file.slice(start, end);
    const buf = new Uint8Array(await slice.arrayBuffer());
    await sendFileChunk(peerId, offerId, i, totalChunks, Array.from(buf));
  }
}
