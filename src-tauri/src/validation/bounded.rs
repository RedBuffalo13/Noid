/// Enforce a maximum length on a string input arriving over the Tauri
/// boundary. Unbounded strings are a DoS vector (DB bloat, DHT record
/// overflow) — every free-text field must pass through this check.
pub fn bounded_str(field: &str, value: &str, max: usize) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{} must not be empty", field));
    }
    if value.len() > max {
        return Err(format!("{} too long (max {} bytes)", field, max));
    }
    Ok(())
}
