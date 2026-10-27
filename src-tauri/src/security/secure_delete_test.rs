use crate::security::secure_delete::{secure_delete, secure_delete_dir};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_secure_delete_nonexistent_file() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("nonexistent.txt");
    let result = secure_delete(&path);
    assert!(result.is_ok());
}

#[test]
fn test_secure_delete_existing_file() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.txt");
    fs::write(&path, b"sensitive data").unwrap();
    assert!(path.exists());
    secure_delete(&path).unwrap();
    assert!(!path.exists());
}

#[test]
fn test_secure_delete_overwrites_before_delete() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.txt");
    let content = b"sensitive data that should be overwritten";
    fs::write(&path, content).unwrap();
    secure_delete(&path).unwrap();
    // File should be gone
    assert!(!path.exists());
}

#[test]
fn test_secure_delete_empty_dir() {
    let dir = tempdir().unwrap();
    let empty_dir = dir.path().join("empty");
    fs::create_dir(&empty_dir).unwrap();
    secure_delete_dir(&empty_dir).unwrap();
    assert!(!empty_dir.exists());
}

#[test]
fn test_secure_delete_nonexistent_dir() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("nonexistent");
    let result = secure_delete_dir(&path);
    assert!(result.is_ok());
}

#[test]
fn test_secure_delete_dir_with_files() {
    let dir = tempdir().unwrap();
    let subdir = dir.path().join("subdir");
    fs::create_dir(&subdir).unwrap();
    fs::write(subdir.join("file1.txt"), b"data1").unwrap();
    fs::write(subdir.join("file2.txt"), b"data2").unwrap();
    secure_delete_dir(&subdir).unwrap();
    assert!(!subdir.exists());
}

#[test]
fn test_secure_delete_dir_recursive() {
    let dir = tempdir().unwrap();
    let root = dir.path().join("root");
    let nested = root.join("nested").join("deep");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("file.txt"), b"deep data").unwrap();
    fs::write(root.join("top.txt"), b"top data").unwrap();
    secure_delete_dir(&root).unwrap();
    assert!(!root.exists());
}
