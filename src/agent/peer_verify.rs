/// Result of peer process verification.
#[derive(Debug)]
pub struct PeerVerification {
    pub pid: i32,
    pub exe_path: String,
    pub signature_valid: bool,
}

/// Immutable peer identity captured when the agent starts. Capturing the
/// policy once prevents a later replacement of the executable path from
/// changing which clients are trusted.
pub struct PeerVerifier {
    #[cfg(target_os = "macos")]
    designated_requirement: String,
    #[cfg(target_os = "linux")]
    self_path: std::path::PathBuf,
}

impl PeerVerifier {
    pub fn new() -> Result<Self, String> {
        let self_exe =
            std::env::current_exe().map_err(|e| format!("current_exe() failed: {}", e))?;

        #[cfg(target_os = "macos")]
        {
            let designated_requirement = get_designated_requirement_via_codesign(&self_exe)
                .map_err(|e| format!("agent requires a code-signed executable: {}", e))?;
            Ok(Self {
                designated_requirement,
            })
        }

        #[cfg(target_os = "linux")]
        {
            let self_path = std::fs::canonicalize(&self_exe)
                .map_err(|e| format!("canonicalize failed: {}", e))?;
            Ok(Self { self_path })
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = self_exe;
            Err("peer binary verification is not supported on this platform".to_string())
        }
    }

    pub fn verify_peer(&self, stream: &tokio::net::UnixStream) -> Result<PeerVerification, String> {
        let pid = get_peer_pid(stream)?;
        let signature_valid = self.verify_process(pid)?;
        let exe_path = get_peer_exe_path(pid)?;

        Ok(PeerVerification {
            pid,
            exe_path,
            signature_valid,
        })
    }

    #[cfg(target_os = "macos")]
    fn verify_process(&self, pid: i32) -> Result<bool, String> {
        verify_running_process(pid, &self.designated_requirement)
    }

    #[cfg(target_os = "linux")]
    fn verify_process(&self, pid: i32) -> Result<bool, String> {
        let peer_exe_path = get_peer_exe_path(pid)?;
        let peer_path = std::fs::canonicalize(peer_exe_path)
            .map_err(|e| format!("canonicalize failed: {}", e))?;
        Ok(self.self_path == peer_path)
    }
}

// Peer verification uses LOCAL_PEERPID and the running code object on macOS, and
// SO_PEERCRED plus a canonical executable path comparison on Linux.
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
fn verify_running_process(pid: i32, requirement_text: &str) -> Result<bool, String> {
    use security_framework::os::macos::code_signing::{
        Flags, GuestAttributes, SecCode, SecRequirement,
    };
    use std::str::FromStr;

    let requirement = SecRequirement::from_str(requirement_text)
        .map_err(|e| format!("invalid designated requirement: {}", e))?;
    let mut attributes = GuestAttributes::new();
    attributes.set_pid(pid);
    let peer_code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
        .map_err(|e| format!("cannot resolve running code for pid {}: {}", pid, e))?;
    let flags = Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS;
    Ok(peer_code.check_validity(flags, &requirement).is_ok())
}

#[cfg(target_os = "macos")]
fn get_designated_requirement_via_codesign(path: &std::path::Path) -> Result<String, String> {
    let output = std::process::Command::new("/usr/bin/codesign")
        .args(["-d", "-r-", "--"])
        .arg(path)
        .output()
        .map_err(|e| format!("failed to execute codesign: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "codesign could not read designated requirement for {}",
            path.display()
        ));
    }

    let mut diagnostic = output.stdout;
    diagnostic.extend_from_slice(&output.stderr);
    let diagnostic = String::from_utf8_lossy(&diagnostic);
    for line in diagnostic.lines() {
        let line = line.trim().strip_prefix("# ").unwrap_or(line.trim());
        if let Some(requirement) = line.strip_prefix("designated => ") {
            let requirement = requirement.trim();
            if !requirement.is_empty() {
                return Ok(requirement.to_string());
            }
        }
    }

    Err(format!(
        "no designated requirement found in codesign output for {}",
        path.display()
    ))
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
        let verifier = PeerVerifier::new().unwrap();
        let result = verifier.verify_process(std::process::id() as i32);
        assert!(result.is_ok(), "failed: {:?}", result);
        // Self-verification should always pass.
        assert!(result.unwrap());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_get_designated_requirement_system_binary() {
        let result = get_designated_requirement_via_codesign(std::path::Path::new("/bin/ls"));
        assert!(result.is_ok(), "failed: {:?}", result);
        let ident = result.unwrap();
        assert!(!ident.is_empty());
    }
}
