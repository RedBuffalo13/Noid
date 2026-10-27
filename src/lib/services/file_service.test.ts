import { describe, it, expect, vi, beforeEach } from "vitest";
import { invokeMock } from "../../test-setup";
import { sendFileOffer, sendFileChunk, sendFile } from "./file_service";

describe("file_service", () => {
  beforeEach(() => {
    invokeMock.mockReset();
  });

  it("sendFileOffer calls invoke with peerId, fileName, fileSize", async () => {
    invokeMock.mockResolvedValue("offer-123");
    const result = await sendFileOffer("peer123", "test.txt", 1024);
    expect(invokeMock).toHaveBeenCalledWith("send_file_offer", {
      peerId: "peer123",
      fileName: "test.txt",
      fileSize: 1024,
    });
    expect(result).toBe("offer-123");
  });

  it("sendFileChunk calls invoke with all params", async () => {
    invokeMock.mockResolvedValue(undefined);
    await sendFileChunk("peer123", "offer-123", 0, 5, [1, 2, 3]);
    expect(invokeMock).toHaveBeenCalledWith("send_file_chunk", {
      peerId: "peer123",
      offerId: "offer-123",
      chunkIndex: 0,
      totalChunks: 5,
      data: [1, 2, 3],
    });
  });

  it("sendFile sends offer then chunks", async () => {
    const chunkSize = 16384;
    const fileSize = chunkSize + 100; // 2 chunks
    const file = new File([new Uint8Array(fileSize)], "test.bin");
    invokeMock.mockResolvedValue("offer-123");

    await sendFile("peer123", file);

    // First call: send_file_offer
    expect(invokeMock).toHaveBeenNthCalledWith(1, "send_file_offer", {
      peerId: "peer123",
      fileName: "test.bin",
      fileSize,
    });

    // Then 2 chunk calls
    expect(invokeMock).toHaveBeenCalledTimes(3); // 1 offer + 2 chunks
  });
});
