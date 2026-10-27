use super::db_test::setup_test_db;

#[tokio::test]
async fn test_add_and_get_shared_folder() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_shared_folder("folder1", "/path/to/folder", true).await.unwrap();
    let folders = db.get_shared_folders().await.unwrap();
    assert_eq!(folders.len(), 1);
    assert_eq!(folders[0].0, "folder1");
    assert_eq!(folders[0].1, "/path/to/folder");
    assert!(folders[0].2);
}

#[tokio::test]
async fn test_update_folder_path() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_shared_folder("folder1", "/old/path", true).await.unwrap();
    db.update_folder_path("folder1", "/new/path").await.unwrap();
    let folders = db.get_shared_folders().await.unwrap();
    assert_eq!(folders[0].1, "/new/path");
}

#[tokio::test]
async fn test_update_folder_visibility() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_shared_folder("folder1", "/path", true).await.unwrap();
    db.update_folder_visibility("folder1", false).await.unwrap();
    let folders = db.get_shared_folders().await.unwrap();
    assert!(!folders[0].2);
}

#[tokio::test]
async fn test_update_and_clear_folder_password() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_shared_folder("folder1", "/path", true).await.unwrap();
    db.update_folder_password("folder1", "hashed_password").await.unwrap();
    let results = db.search_shared_folders("path").await.unwrap();
    assert_eq!(results[0].3, Some("hashed_password".to_string()));

    db.clear_folder_password("folder1").await.unwrap();
    let results = db.search_shared_folders("path").await.unwrap();
    assert_eq!(results[0].3, None);
}

#[tokio::test]
async fn test_delete_shared_folder() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_shared_folder("folder1", "/path", true).await.unwrap();
    db.delete_shared_folder("folder1").await.unwrap();
    let folders = db.get_shared_folders().await.unwrap();
    assert_eq!(folders.len(), 0);
}

#[tokio::test]
async fn test_search_shared_folders() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_shared_folder("folder1", "/path/to/music", true).await.unwrap();
    db.add_shared_folder("folder2", "/path/to/docs", false).await.unwrap();
    let results = db.search_shared_folders("music").await.unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].0, "folder1");
}
