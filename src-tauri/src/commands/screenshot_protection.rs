#[cfg(any(target_os = "windows", target_os = "macos"))]
use tauri::Manager;
use tauri::State;
use crate::AppState;

#[tauri::command]
#[allow(unused_variables)]
pub async fn enable_screenshot_protection(
    app: tauri::AppHandle,
    _state: State<'_, AppState>,
) -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        if let Some(window) = app.get_webview_window("main") {
            use std::ffi::c_int;
            const WDA_EXCLUDEFROMCAPTURE: u32 = 0x11;
            const DWMWA_EXCLUDED_FROM_CAPTURE: u32 = 17;
            extern "system" {
                fn SetWindowDisplayAffinity(hwnd: isize, affinity: u32) -> i32;
                fn DwmSetWindowAttribute(
                    hwnd: isize,
                    attr: u32,
                    value: *const c_int,
                    cbAttribute: u32,
                ) -> i32;
            }
            let hwnd = window.hwnd().map_err(|e| e.to_string())?.0 as isize;
            // SetWindowDisplayAffinity works since Windows 7 — the primary
            // mechanism. DwmSetWindowAttribute(17) is a Win11 22H2+ nicety
            // applied on top; its result is intentionally not checked.
            let ok = unsafe { SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) };
            if ok == 0 {
                return Err("SetWindowDisplayAffinity failed".to_string());
            }
            let value: c_int = 1;
            unsafe {
                DwmSetWindowAttribute(
                    hwnd,
                    DWMWA_EXCLUDED_FROM_CAPTURE,
                    &value,
                    std::mem::size_of::<c_int>() as u32,
                );
            }
            log::info!("Screenshot protection enabled (Windows)");
            // Phase J.4: Log screenshot protection change
            let _ = _state.audit_log.log_screenshot_protection(true);
            return Ok(true);
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.set_content_protected(true);
            log::info!("Screenshot protection enabled (macOS)");
            // Phase J.4: Log screenshot protection change
            let _ = _state.audit_log.log_screenshot_protection(true);
            return Ok(true);
        }
    }

    #[cfg(target_os = "android")]
    {
        android_set_secure(true)?;
        log::info!("Screenshot protection enabled (Android FLAG_SECURE)");
        let _ = _state.audit_log.log_screenshot_protection(true);
        return Ok(true);
    }

    #[cfg(not(any(target_os = "android", target_os = "macos", target_os = "windows")))]
    {
        log::warn!("Screenshot protection not supported on this platform");
        return Ok(false);
    }

    #[allow(unreachable_code)]
    Ok(false)
}

#[tauri::command]
#[allow(unused_variables)]
pub async fn disable_screenshot_protection(
    app: tauri::AppHandle,
    _state: State<'_, AppState>,
) -> Result<bool, String> {
    #[cfg(target_os = "windows")]
    {
        if let Some(window) = app.get_webview_window("main") {
            use std::ffi::c_int;
            const WDA_NONE: u32 = 0;
            const DWMWA_EXCLUDED_FROM_CAPTURE: u32 = 17;
            extern "system" {
                fn SetWindowDisplayAffinity(hwnd: isize, affinity: u32) -> i32;
                fn DwmSetWindowAttribute(
                    hwnd: isize,
                    attr: u32,
                    value: *const c_int,
                    cbAttribute: u32,
                ) -> i32;
            }
            let hwnd = window.hwnd().map_err(|e| e.to_string())?.0 as isize;
            let ok = unsafe { SetWindowDisplayAffinity(hwnd, WDA_NONE) };
            if ok == 0 {
                return Err("SetWindowDisplayAffinity failed".to_string());
            }
            let value: c_int = 0;
            unsafe {
                DwmSetWindowAttribute(
                    hwnd,
                    DWMWA_EXCLUDED_FROM_CAPTURE,
                    &value,
                    std::mem::size_of::<c_int>() as u32,
                );
            }
            log::info!("Screenshot protection disabled (Windows)");
            // Phase J.4: Log screenshot protection change
            let _ = _state.audit_log.log_screenshot_protection(false);
            return Ok(true);
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.set_content_protected(false);
            log::info!("Screenshot protection disabled (macOS)");
            // Phase J.4: Log screenshot protection change
            let _ = _state.audit_log.log_screenshot_protection(false);
            return Ok(true);
        }
    }

    #[cfg(target_os = "android")]
    {
        android_set_secure(false)?;
        log::info!("Screenshot protection disabled (Android)");
        let _ = _state.audit_log.log_screenshot_protection(false);
        return Ok(true);
    }

    #[cfg(not(any(target_os = "android", target_os = "macos", target_os = "windows")))]
    {
        log::warn!("Screenshot protection not supported on this platform");
        return Ok(false);
    }

    #[allow(unreachable_code)]
    Ok(false)
}

/// Toggle Android's `WindowManager.LayoutParams.FLAG_SECURE` on the main
/// activity window through the Kotlin helper `NoidNative.setSecure`.
#[cfg(target_os = "android")]
fn android_set_secure(enabled: bool) -> Result<(), String> {
    use jni::objects::{JObject, JValue};
    let ctx = ndk_context::android_context();
    let vm = unsafe { jni::JavaVM::from_raw(ctx.vm() as *mut _) }
        .map_err(|e| format!("JavaVM: {}", e))?;
    let mut env = vm
        .attach_current_thread()
        .map_err(|e| format!("attach thread: {}", e))?;
    let context = unsafe { JObject::from_raw(ctx.context() as jni::sys::jobject) };
    // AN-02: a Tokio-attached thread has no Java frames — find_class /
    // call_static_method by name resolves through the BootClassLoader,
    // which cannot see app classes and always throws
    // ClassNotFoundException. Load the class through the CONTEXT's
    // ClassLoader instead — it is the app's own loader.
    let loader = env
        .call_method(&context, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])
        .and_then(|v| v.l())
        .map_err(|e| format!("getClassLoader: {}", e))?;
    let name = env
        .new_string("com.bst.noid.NoidNative")
        .map_err(|e| format!("new_string: {}", e))?;
    let cls = env
        .call_method(
            loader,
            "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;",
            &[JValue::Object(&name)],
        )
        .and_then(|v| v.l())
        .map_err(|e| format!("loadClass NoidNative: {}", e))?;
    let cls: &jni::objects::JClass = (&cls).into();
    env.call_static_method(
        cls,
        "setSecure",
        "(Landroid/content/Context;Z)V",
        &[JValue::Object(&context), JValue::Bool(enabled as u8)],
    )
    .map_err(|e| format!("JNI setSecure: {}", e))?;
    Ok(())
}
