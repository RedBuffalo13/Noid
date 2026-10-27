//! System tray icon: close button hides the window to the tray instead of
//! quitting — the P2P node keeps running in the background. Real exit is
//! only via the tray menu's Quit entry.
//!
//! Platform notes: Windows — classic tray; macOS — status bar item (Dock
//! icon remains); Linux — AppIndicator/KStatusNotifier (on GNOME without
//! an extension the icon may not render; the window still hides and can be
//! restored by relaunching — covered by single-instance).

use tauri::{
    menu::{MenuBuilder, MenuItemBuilder},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager,
};

const ID_SHOW: &str = "tray-show";
const ID_QUIT: &str = "tray-quit";

/// Show and focus the main window (restores a minimized window on Windows).
fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Build the tray icon with its context menu. Called once during setup.
pub fn setup_tray(app: &tauri::App) -> anyhow::Result<()> {
    let show_item = MenuItemBuilder::with_id(ID_SHOW, "Показать Noid").build(app)?;
    let quit_item = MenuItemBuilder::with_id(ID_QUIT, "Выход").build(app)?;
    let menu = MenuBuilder::new(app)
        .item(&show_item)
        .separator()
        .item(&quit_item)
        .build()?;

    let mut builder = TrayIconBuilder::new()
        .tooltip("Noid Messenger")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            ID_SHOW => show_main_window(app),
            ID_QUIT => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });

    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }

    builder.build(app)?;
    Ok(())
}
