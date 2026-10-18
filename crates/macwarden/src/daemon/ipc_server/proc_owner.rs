//! Resolve a process's owning username unprivileged (macOS).
//!
//! Neither `sysinfo` nor `proc_pidinfo(PROC_PIDTBSDINFO)` can read the uid of a
//! *root-owned* process from an unprivileged caller — both return "no info". But
//! `sysctl(KERN_PROC_PID)` can (it is how `ps` shows every process's user). This
//! reads that `kinfo_proc` and extracts `kp_eproc.e_ucred.cr_uid`, then resolves
//! it to a name via `getpwuid` (cached per uid).
//!
//! The `kinfo_proc` layout is a stable legacy ABI, but rather than trust a
//! hand-derived offset blindly, a one-time **self-check** validates it: the uid
//! read for our own pid must equal `geteuid()`. If it does not (a layout drift on
//! some future OS), the resolver disables itself and callers fall back to "—" —
//! so a wrong offset can never surface a *wrong* username, only "unknown".

/// The owning username for `pid`, or `None` when unresolvable (process gone, or
/// the platform/ABI self-check failed). macOS-only; other targets return `None`.
#[must_use]
pub fn owner_username(pid: u32) -> Option<String> {
    imp::owner_username(pid)
}

#[cfg(target_os = "macos")]
mod imp {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    /// `struct _ucred` — the credentials block inside `kinfo_proc.kp_eproc`.
    /// Layout-only (matched to the C ABI); read via `offset_of`, not by field.
    #[repr(C)]
    #[allow(dead_code, clippy::struct_field_names)]
    struct Ucred {
        cr_ref: i32,
        cr_uid: u32,
        cr_ngroups: i16,
        cr_groups: [u32; 16],
    }

    /// A prefix of `kinfo_proc` up to `kp_eproc.e_ucred.cr_uid`. The opaque arrays
    /// are the 64-bit sizes of `struct extern_proc` (`kp_proc`) and `struct
    /// _pcred` (`e_pcred`); the compiler then computes `cr_uid`'s offset, and the
    /// runtime self-check confirms the whole layout against reality. Layout-only.
    #[repr(C)]
    #[allow(dead_code)]
    struct KinfoPrefix {
        kp_proc: [u8; 296],
        e_paddr: usize,
        e_sess: usize,
        e_pcred: [u8; 104],
        e_ucred: Ucred,
    }

    pub fn owner_username(pid: u32) -> Option<String> {
        if !enabled() {
            return None;
        }
        let uid = uid_of(pid)?;
        username_cached(uid)
    }

    /// Whether the sysctl uid path is trustworthy on this system: read once,
    /// validated by requiring our own pid's uid to equal `geteuid()`.
    fn enabled() -> bool {
        static OK: OnceLock<bool> = OnceLock::new();
        *OK.get_or_init(|| uid_of(std::process::id()) == Some(current_euid()))
    }

    /// The euid of this process.
    #[allow(unsafe_code)]
    fn current_euid() -> u32 {
        // SAFETY: `geteuid` takes no arguments, reads no memory, and cannot fail.
        unsafe { libc::geteuid() }
    }

    /// Read a pid's real uid via `sysctl(KERN_PROC_PID)`, which is readable for
    /// every process by an unprivileged caller.
    #[allow(unsafe_code)]
    fn uid_of(pid: u32) -> Option<u32> {
        let off = std::mem::offset_of!(KinfoPrefix, e_ucred.cr_uid);
        let mut buf = [0u8; 1024];
        let mut size = buf.len();
        let mut mib = [
            libc::CTL_KERN,
            libc::KERN_PROC,
            libc::KERN_PROC_PID,
            pid as i32,
        ];
        // SAFETY: `mib` holds 4 valid ints; `buf` is a 1024-byte writable buffer
        // and `size` its capacity (kinfo_proc is far smaller); `sysctl` writes at
        // most `size` bytes and updates it. No input data pointer is passed.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                4,
                buf.as_mut_ptr().cast(),
                &raw mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 || size < off + 4 {
            return None;
        }
        let bytes: [u8; 4] = buf.get(off..off + 4)?.try_into().ok()?;
        Some(u32::from_ne_bytes(bytes))
    }

    /// Resolve a uid to a username, caching the (few, stable) results so a busy
    /// sample doesn't re-hit `getpwuid` for every process.
    fn username_cached(uid: u32) -> Option<String> {
        static CACHE: OnceLock<Mutex<HashMap<u32, Option<String>>>> = OnceLock::new();
        let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        if let Ok(map) = cache.lock()
            && let Some(hit) = map.get(&uid)
        {
            return hit.clone();
        }
        let resolved = username(uid);
        if let Ok(mut map) = cache.lock() {
            map.insert(uid, resolved.clone());
        }
        resolved
    }

    /// Look up a uid's login name via `getpwuid`.
    #[allow(unsafe_code)]
    fn username(uid: u32) -> Option<String> {
        // SAFETY: `getpwuid` takes a uid and returns a pointer to static passwd
        // storage (or null). No memory is passed in.
        let pw = unsafe { libc::getpwuid(uid) };
        if pw.is_null() {
            return None;
        }
        // SAFETY: `pw` is non-null here; `pw_name` is a valid pointer within the
        // passwd entry's static storage.
        let name_ptr = unsafe { (*pw).pw_name };
        if name_ptr.is_null() {
            return None;
        }
        // SAFETY: `pw_name` is a valid NUL-terminated C string, read immediately
        // before any other `getpw*` call could overwrite the static buffer.
        let cstr = unsafe { std::ffi::CStr::from_ptr(name_ptr) };
        cstr.to_str().ok().map(str::to_owned)
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    pub fn owner_username(_pid: u32) -> Option<String> {
        None
    }
}

#[cfg(all(test, target_os = "macos"))]
#[path = "proc_owner_test.rs"]
mod proc_owner_test;
