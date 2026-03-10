/// Result of peer process verification.
#[derive(Debug)]
pub struct PeerVerification {
    pub pid: i32,
    pub exe_path: String,
    pub signature_valid: bool,
}

/// Verify the peer process of a Unix domain socket connection.
/// On macOS: LOCAL_PEERPID -> proc_pidpath -> code signature verification.
/// On Linux: SO_PEERCRED -> /proc/PID/exe -> path match verification.
pub fn verify_peer(stream: &tokio::net::UnixStream) -> Result<PeerVerification, String> {
    let pid = get_peer_pid(stream)?;
    let exe_path = get_peer_exe_path(pid)?;
    let signature_valid = verify_binary(&exe_path)?;

    Ok(PeerVerification {
        pid,
        exe_path,
        signature_valid,
    })
}

// ── PID 取得 ──

#[cfg(target_os = "macos")]
fn get_peer_pid(stream: &tokio::net::UnixStream) -> Result<i32, String> {
    use std::os::unix::io::AsRawFd;

    // macOS: SOL_LOCAL = 0, LOCAL_PEERPID = 0x002
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERPID: libc::c_int = 0x002;

    let fd = stream.as_raw_fd();
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;

    // SAFETY: fd is a valid socket file descriptor from the accepted connection.
    // pid and len are valid mutable pointers with correct sizes.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERPID,
            &mut pid as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if ret != 0 {
        return Err(format!(
            "getsockopt(LOCAL_PEERPID) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(pid)
}

#[cfg(target_os = "linux")]
fn get_peer_pid(stream: &tokio::net::UnixStream) -> Result<i32, String> {
    let cred = stream
        .peer_cred()
        .map_err(|e| format!("peer_cred() failed: {}", e))?;
    cred.pid()
        .ok_or_else(|| "peer PID not available".to_string())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn get_peer_pid(_stream: &tokio::net::UnixStream) -> Result<i32, String> {
    Err("peer PID verification is not supported on this platform".to_string())
}

// ── 実行パス取得 ──

#[cfg(target_os = "macos")]
fn get_peer_exe_path(pid: i32) -> Result<String, String> {
    libproc::libproc::proc_pid::pidpath(pid)
        .map_err(|e| format!("proc_pidpath({}) failed: {}", pid, e))
}

#[cfg(target_os = "linux")]
fn get_peer_exe_path(pid: i32) -> Result<String, String> {
    let link = format!("/proc/{}/exe", pid);
    std::fs::read_link(&link)
        .map(|p| p.to_string_lossy().to_string())
        .map_err(|e| format!("readlink({}) failed: {}", link, e))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn get_peer_exe_path(_pid: i32) -> Result<String, String> {
    Err("peer exe path verification is not supported on this platform".to_string())
}

// ── バイナリ検証 ──

#[cfg(target_os = "macos")]
fn verify_binary(peer_exe_path: &str) -> Result<bool, String> {
    let self_exe = std::env::current_exe()
        .map_err(|e| format!("current_exe() failed: {}", e))?
        .to_string_lossy()
        .to_string();

    // If both paths are the same, skip signature verification.
    if self_exe == peer_exe_path {
        return Ok(true);
    }

    // Validate the peer binary's code signature and check that both binaries
    // share the same signing identity using SecRequirement.
    match (is_signed(&self_exe), is_signed(peer_exe_path)) {
        // Both signed: verify the peer matches daemon's signing identifier.
        (true, true) => verify_same_signing_identity(&self_exe, peer_exe_path),
        // Both unsigned: allow (development scenario).
        (false, false) => Ok(true),
        // One signed, one not: deny.
        _ => Ok(false),
    }
}

/// Check if a binary at the given path has a valid code signature.
#[cfg(target_os = "macos")]
fn is_signed(path: &str) -> bool {
    use core_foundation::base::TCFType;
    use core_foundation::url::CFURL;
    use security_framework_sys::code_signing::*;
    use std::ptr;

    let url = match CFURL::from_path(std::path::Path::new(path), false) {
        Some(u) => u,
        None => return false,
    };

    let mut static_code: SecStaticCodeRef = ptr::null_mut();
    let status =
        unsafe { SecStaticCodeCreateWithPath(url.as_concrete_TypeRef(), 0, &mut static_code) };
    if status != 0 || static_code.is_null() {
        return false;
    }

    let valid = unsafe { SecStaticCodeCheckValidity(static_code, 0, ptr::null_mut()) };
    unsafe { core_foundation_sys::base::CFRelease(static_code as *const _) };

    valid == 0
}

/// Verify that two binaries have the same signing identity by extracting the
/// daemon's identifier and checking the peer against it via SecRequirement.
#[cfg(target_os = "macos")]
fn verify_same_signing_identity(self_path: &str, peer_path: &str) -> Result<bool, String> {
    use core_foundation::base::TCFType;
    use core_foundation::string::CFString;
    use core_foundation::url::CFURL;
    use core_foundation_sys::base::CFRelease;
    use security_framework_sys::code_signing::*;
    use std::ptr;

    // Get daemon's signing identifier via codesign command.
    // This is simpler and more reliable than FFI for SecCodeCopySigningInformation.
    let self_ident = get_signing_identifier_via_codesign(self_path)?;

    // Sanitize identifier to prevent SecRequirement string injection.
    if !self_ident
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Err(format!("invalid signing identifier: {}", self_ident));
    }

    // Build a SecRequirement that matches the identifier.
    let req_str = format!("identifier \"{}\"", self_ident);
    let cf_req_str = CFString::new(&req_str);
    let mut requirement: SecRequirementRef = ptr::null_mut();
    let status = unsafe {
        SecRequirementCreateWithString(cf_req_str.as_concrete_TypeRef(), 0, &mut requirement)
    };
    if status != 0 || requirement.is_null() {
        return Err(format!(
            "SecRequirementCreateWithString failed: OSStatus {}",
            status
        ));
    }

    // Validate peer binary against this requirement.
    let peer_url = CFURL::from_path(std::path::Path::new(peer_path), false)
        .ok_or_else(|| format!("failed to create CFURL for {}", peer_path))?;

    let mut peer_code: SecStaticCodeRef = ptr::null_mut();
    let create_status =
        unsafe { SecStaticCodeCreateWithPath(peer_url.as_concrete_TypeRef(), 0, &mut peer_code) };
    if create_status != 0 || peer_code.is_null() {
        unsafe { CFRelease(requirement as *const _) };
        return Err(format!(
            "SecStaticCodeCreateWithPath failed for {}: OSStatus {}",
            peer_path, create_status
        ));
    }

    let check_status = unsafe { SecStaticCodeCheckValidity(peer_code, 0, requirement) };

    unsafe {
        CFRelease(peer_code as *const _);
        CFRelease(requirement as *const _);
    };

    Ok(check_status == 0)
}

/// Get the signing identifier of a binary using the `codesign` command.
/// This avoids the need for `SecCodeCopySigningInformation` FFI bindings.
#[cfg(target_os = "macos")]
fn get_signing_identifier_via_codesign(path: &str) -> Result<String, String> {
    let output = std::process::Command::new("/usr/bin/codesign")
        .args(["-d", "-vvv", path])
        .output()
        .map_err(|e| format!("failed to execute codesign: {}", e))?;

    // codesign -d outputs to stderr.
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Parse "Identifier=<identifier>" from the output.
    for line in stderr.lines() {
        if let Some(ident) = line.strip_prefix("Identifier=") {
            return Ok(ident.trim().to_string());
        }
    }

    Err(format!(
        "no Identifier found in codesign output for {}",
        path
    ))
}

#[cfg(target_os = "linux")]
fn verify_binary(peer_exe_path: &str) -> Result<bool, String> {
    // Linux fallback: compare exe paths.
    let self_exe = std::env::current_exe().map_err(|e| format!("current_exe() failed: {}", e))?;
    let self_path = std::fs::canonicalize(&self_exe)
        .map_err(|e| format!("canonicalize failed: {}", e))?
        .to_string_lossy()
        .to_string();
    let peer_path = std::fs::canonicalize(peer_exe_path)
        .map_err(|e| format!("canonicalize failed: {}", e))?
        .to_string_lossy()
        .to_string();
    Ok(self_path == peer_path)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn verify_binary(_peer_exe_path: &str) -> Result<bool, String> {
    // Unsupported platform: skip verification.
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_peer_exe_path_self() {
        let pid = std::process::id() as i32;
        let result = get_peer_exe_path(pid);
        assert!(result.is_ok(), "failed: {:?}", result);
        let path = result.unwrap();
        assert!(!path.is_empty());
    }

    #[test]
    fn test_verify_binary_self() {
        let self_exe = std::env::current_exe().unwrap();
        let result = verify_binary(self_exe.to_str().unwrap());
        assert!(result.is_ok(), "failed: {:?}", result);
        // Self-verification should always pass.
        assert!(result.unwrap());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_is_signed_system_binary() {
        // /bin/ls should be signed by Apple on macOS.
        assert!(is_signed("/bin/ls"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_get_signing_identifier_system_binary() {
        let result = get_signing_identifier_via_codesign("/bin/ls");
        assert!(result.is_ok(), "failed: {:?}", result);
        let ident = result.unwrap();
        assert!(!ident.is_empty());
    }
}
