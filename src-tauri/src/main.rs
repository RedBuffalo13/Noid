// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

/// No usable GUI display on this host — Linux/Unix without X11/Wayland.
/// Windows/macOS always report false: their headless contexts are rare and
/// a false positive would turn a desktop launch into a silent relay.
fn no_display() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

// IPC-05: no #[tokio::main] — in GUI mode tauri::Builder::run() creates
// the single async runtime the app needs; an outer runtime only doubled
// the worker pool and let spawned code capture the wrong Handle. The
// headless relay branch builds its runtime explicitly instead.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let force_relay = args.iter().any(|a| a == "--relay" || a == "--headless");
    let force_gui = args.iter().any(|a| a == "--gui");
    // Bare `noid` self-selects: headless host → relay, display → GUI.
    // Auxiliary flags (--data-dir, --init, --port, ...) never force the GUI.
    let headless = !force_gui && (force_relay || no_display());

    if headless {
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("Failed to start async runtime: {}", e);
                std::process::exit(1);
            }
        };
        if let Err(e) = rt.block_on(noid_lib::relay_headless::run(&args)) {
            eprintln!("Relay failed: {}", e);
            std::process::exit(1);
        }
    } else {
        if no_display() {
            // --gui was requested on a host with no display — tao would panic
            // inside GTK init. Fail with a readable hint instead.
            eprintln!(
                "No display detected (DISPLAY/WAYLAND_DISPLAY unset). \
                 Run without --gui on a desktop, or use `noid --relay` headless."
            );
            std::process::exit(2);
        }
        noid_lib::run()
    }
}
