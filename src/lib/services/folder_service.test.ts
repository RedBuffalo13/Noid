import { describe, it, expect, vi, beforeEach } from "vitest";
import { invokeMock } from "../../test-setup";
import {
  updateFolderPath,
  updateFolderVisibility,
  updateFolderPassword,
  deleteSharedFolder,
  searchSharedFolders,
} from "./folder_service";

describe("folder_service", () => {
  beforeEach(() => {
    invokeMock.mockReset();
  });

  it("updateFolderPath calls invoke with id and newPath", async () => {
    invokeMock.mockResolvedValue(undefined);
    await updateFolderPath("folder1", "/new/path");
    expect(invokeMock).toHaveBeenCalledWith("update_folder_path", {
      id: "folder1",
      newPath: "/new/path",
    });
  });

  it("updateFolderVisibility calls invoke with id and isPublic", async () => {
    invokeMock.mockResolvedValue(undefined);
    await updateFolderVisibility("folder1", true);
    expect(invokeMock).toHaveBeenCalledWith("update_folder_visibility", {
      id: "folder1",
      isPublic: true,
    });
  });

  it("updateFolderPassword calls invoke with id and password", async () => {
    invokeMock.mockResolvedValue(undefined);
    await updateFolderPassword("folder1", "secret");
    expect(invokeMock).toHaveBeenCalledWith("update_folder_password", {
      id: "folder1",
      password: "secret",
    });
  });

  it("deleteSharedFolder calls invoke with id", async () => {
    invokeMock.mockResolvedValue(undefined);
    await deleteSharedFolder("folder1");
    expect(invokeMock).toHaveBeenCalledWith("delete_shared_folder", {
      id: "folder1",
    });
  });

  it("searchSharedFolders calls invoke with query", async () => {
    invokeMock.mockResolvedValue([]);
    await searchSharedFolders("test");
    expect(invokeMock).toHaveBeenCalledWith("search_shared_folders", {
      query: "test",
    });
  });
});
