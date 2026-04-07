//! Raw FFI bindings to `libproc`, Security.framework, and CoreFoundation.
//!
//! **All unsafe code in the procmon crate lives in this module.**
//!
//! This module is `cfg(target_os = "macos")` -- it only compiles on macOS.
//! Safe wrappers in sibling modules call these functions with validated
//! inputs and handle all error cases.
//!
//! # Struct layouts
//!
//! All `#[repr(C)]` struct sizes were verified against the macOS SDK
//! header `sys/proc_info.h` using a C size-check program. The union
//! `soi_proto` is represented as a fixed-size byte array matching the
//! largest union variant (`un_sockinfo` = 528 bytes).
//!
//! # Linking
//!
//! - `libproc` functions link automatically via libSystem.
//! - `responsibility_get_pid_responsible_for_pid` links via libSystem.
//! - Security.framework and CoreFoundation.framework use `#[link]`.

#![cfg(target_os = "macos")]
#![allow(unsafe_code, dead_code, clippy::struct_field_names)]

use std::os::raw::{c_char, c_int, c_void};

// ---------------------------------------------------------------------------
// libproc constants
// ---------------------------------------------------------------------------

/// Flavor for `proc_pidinfo`: list file descriptors.
pub const PROC_PIDLISTFDS: c_int = 1;

/// Flavor for `proc_pidfdinfo`: get socket info for an fd.
pub const PROC_PIDFDSOCKETINFO: c_int = 3;

/// File descriptor type: socket.
pub const PROX_FDTYPE_SOCKET: u32 = 2;

/// Maximum path buffer size for `proc_pidpath`.
pub const PROC_PIDPATHINFO_MAXSIZE: u32 = 4096;

/// `rusage_info` flavor v4.
pub const RUSAGE_INFO_V4: c_int = 4;

// ---------------------------------------------------------------------------
// Socket family / protocol constants
// ---------------------------------------------------------------------------

/// IPv4 address family.
pub const AF_INET: i32 = 2;

/// IPv6 address family.
pub const AF_INET6: i32 = 30;

/// TCP protocol number.
pub const IPPROTO_TCP: i32 = 6;

/// UDP protocol number.
pub const IPPROTO_UDP: i32 = 17;

// ---------------------------------------------------------------------------
// TCP state constants (from sys/proc_info.h TSI_S_*)
// ---------------------------------------------------------------------------

/// Closed.
pub const TSI_S_CLOSED: i32 = 0;
/// Listening.
pub const TSI_S_LISTEN: i32 = 1;
/// SYN sent.
pub const TSI_S_SYN_SENT: i32 = 2;
/// SYN received.
pub const TSI_S_SYN_RECEIVED: i32 = 3;
/// Established.
pub const TSI_S_ESTABLISHED: i32 = 4;
/// Close wait.
pub const TSI_S_CLOSE_WAIT: i32 = 5;
/// Time wait.
pub const TSI_S_TIME_WAIT: i32 = 10;

// ---------------------------------------------------------------------------
// Socket info kind constants
// ---------------------------------------------------------------------------

/// Generic socket info (no protocol-specific data).
pub const SOCKINFO_TCP: i32 = 2;

// ---------------------------------------------------------------------------
// in_sockinfo vflag constants
// ---------------------------------------------------------------------------

/// Socket uses IPv4.
pub const INI_IPV4: u8 = 0x1;

/// Socket uses IPv6.
pub const INI_IPV6: u8 = 0x2;

// ---------------------------------------------------------------------------
// libproc structs -- sizes verified against macOS SDK
// ---------------------------------------------------------------------------

/// File descriptor entry returned by `proc_pidinfo(PROC_PIDLISTFDS)`.
/// Size: 8 bytes (verified).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct proc_fdinfo {
    /// File descriptor number.
    pub proc_fd: i32,
    /// File descriptor type (e.g. `PROX_FDTYPE_SOCKET`).
    pub proc_fdtype: u32,
}

/// File info header embedded in every `*_fdinfo` struct.
/// Size: 24 bytes (verified).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct proc_fileinfo {
    /// Open flags.
    pub fi_openflags: u32,
    /// Status flags.
    pub fi_status: u32,
    /// Current offset.
    pub fi_offset: i64,
    /// File type.
    pub fi_type: i32,
    /// Guard flags.
    pub fi_guardflags: u32,
}

/// Send/receive buffer info. Size: 24 bytes (verified).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct sockbuf_info {
    /// Current byte count in buffer.
    pub sbi_cc: u32,
    /// High water mark.
    pub sbi_hiwat: u32,
    /// Mbuf byte count.
    pub sbi_mbcnt: u32,
    /// Mbuf max.
    pub sbi_mbmax: u32,
    /// Low water mark.
    pub sbi_lowat: u32,
    /// Flags.
    pub sbi_flags: i16,
    /// Timeout.
    pub sbi_timeo: i16,
}

/// Stat info for vnodes, sockets, etc. Size: 136 bytes (verified).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct vinfo_stat {
    /// Device ID.
    pub vst_dev: u32,
    /// Mode.
    pub vst_mode: u16,
    /// Hard link count.
    pub vst_nlink: u16,
    /// Inode number.
    pub vst_ino: u64,
    /// User ID.
    pub vst_uid: u32,
    /// Group ID.
    pub vst_gid: u32,
    /// Access time (seconds).
    pub vst_atime: i64,
    /// Access time (nanoseconds).
    pub vst_atimensec: i64,
    /// Modification time (seconds).
    pub vst_mtime: i64,
    /// Modification time (nanoseconds).
    pub vst_mtimensec: i64,
    /// Status change time (seconds).
    pub vst_ctime: i64,
    /// Status change time (nanoseconds).
    pub vst_ctimensec: i64,
    /// Birth time (seconds).
    pub vst_birthtime: i64,
    /// Birth time (nanoseconds).
    pub vst_birthtimensec: i64,
    /// File size in bytes.
    pub vst_size: i64,
    /// Blocks allocated.
    pub vst_blocks: i64,
    /// Optimal block size.
    pub vst_blksize: i32,
    /// User flags.
    pub vst_flags: u32,
    /// Generation number.
    pub vst_gen: u32,
    /// Device ID for special files.
    pub vst_rdev: u32,
    /// Reserved.
    pub vst_qspare: [i64; 2],
}

/// IPv4-in-IPv6 address wrapper. Size: 16 bytes (verified).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct in4in6_addr {
    /// Padding (3 x u32 = 12 bytes).
    pub i46a_pad32: [u32; 3],
    /// IPv4 address (4 bytes, network byte order).
    pub i46a_addr4: [u8; 4],
}

/// IPv6 address (16 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct in6_addr_bytes {
    /// 16-byte IPv6 address.
    pub bytes: [u8; 16],
}

/// Union of IPv4-in-IPv6 and raw IPv6. Size: 16 bytes.
/// We represent this as a 16-byte array and interpret based on `insi_vflag`.
#[repr(C)]
#[derive(Clone, Copy)]
pub union in_addr_union {
    /// IPv4 mapped in IPv6 container.
    pub ina_46: in4in6_addr,
    /// Raw IPv6 address.
    pub ina_6: in6_addr_bytes,
}

/// Internet socket info. Size: 80 bytes (verified).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct in_sockinfo {
    /// Foreign (remote) port.
    pub insi_fport: i32,
    /// Local port.
    pub insi_lport: i32,
    /// Generation count.
    pub insi_gencnt: u64,
    /// Generic flags.
    pub insi_flags: u32,
    /// Flow label.
    pub insi_flow: u32,
    /// Version flag: `INI_IPV4` or `INI_IPV6`.
    pub insi_vflag: u8,
    /// IP TTL.
    pub insi_ip_ttl: u8,
    /// Padding to align to 4-byte boundary + rfu_1.
    pub _pad: [u8; 2],
    /// Reserved field (rfu_1).
    pub _rfu_1: u32,
    /// Foreign (remote) address.
    pub insi_faddr: in_addr_union,
    /// Local address.
    pub insi_laddr: in_addr_union,
    /// IPv4-specific fields (tos). Offset 64, size 1 + padding.
    pub insi_v4_tos: u8,
    /// Padding after v4 TOS.
    pub _v4_pad: [u8; 3],
    /// IPv6-specific fields. Offset 68.
    pub insi_v6_hlim: u8,
    /// Padding.
    pub _v6_pad1: [u8; 3],
    /// IPv6 checksum.
    pub insi_v6_cksum: i32,
    /// IPv6 interface index.
    pub insi_v6_ifindex: u16,
    /// IPv6 hops.
    pub insi_v6_hops: i16,
}

/// TCP socket info. Size: 120 bytes (verified).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct tcp_sockinfo {
    /// Embedded internet socket info.
    pub tcpsi_ini: in_sockinfo,
    /// TCP state (TSI_S_* constants).
    pub tcpsi_state: i32,
    /// Timers.
    pub tcpsi_timer: [i32; 4],
    /// Max segment size.
    pub tcpsi_mss: i32,
    /// TCP flags.
    pub tcpsi_flags: u32,
    /// Reserved.
    pub _rfu_1: u32,
    /// Opaque handle to TCP PCB.
    pub tcpsi_tp: u64,
}

/// The `soi_proto` union in `socket_info`. Size: 528 bytes (verified).
///
/// The largest variant is `un_sockinfo` at 528 bytes. We use a byte
/// array and interpret via `soi_kind`.
#[repr(C)]
#[derive(Clone, Copy)]
pub union soi_proto_union {
    /// TCP socket info (kind = SOCKINFO_TCP).
    pub pri_tcp: tcp_sockinfo,
    /// Internet socket info (kind = SOCKINFO_IN).
    pub pri_in: in_sockinfo,
    /// Raw bytes for variants we don't parse.
    pub _raw: [u8; 528],
}

/// Full socket info struct. Size: 768 bytes (verified).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct socket_info {
    /// Stat info.
    pub soi_stat: vinfo_stat,
    /// Opaque socket handle.
    pub soi_so: u64,
    /// Opaque PCB handle.
    pub soi_pcb: u64,
    /// Socket type (SOCK_STREAM, SOCK_DGRAM, etc.).
    pub soi_type: i32,
    /// Protocol number (IPPROTO_TCP, IPPROTO_UDP).
    pub soi_protocol: i32,
    /// Address family (AF_INET, AF_INET6).
    pub soi_family: i32,
    /// Socket options.
    pub soi_options: i16,
    /// Linger time.
    pub soi_linger: i16,
    /// Socket state flags.
    pub soi_state: i16,
    /// Current queue length.
    pub soi_qlen: i16,
    /// Incomplete queue length.
    pub soi_incqlen: i16,
    /// Queue limit.
    pub soi_qlimit: i16,
    /// Timeout.
    pub soi_timeo: i16,
    /// Error code.
    pub soi_error: u16,
    /// Out-of-band mark.
    pub soi_oobmark: u32,
    /// Receive buffer info.
    pub soi_rcv: sockbuf_info,
    /// Send buffer info.
    pub soi_snd: sockbuf_info,
    /// Socket info kind (SOCKINFO_TCP, SOCKINFO_IN, etc.).
    pub soi_kind: i32,
    /// Reserved.
    pub _rfu_1: u32,
    /// Protocol-specific info (union).
    pub soi_proto: soi_proto_union,
}

/// Socket file descriptor info. Size: 792 bytes (verified).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct socket_fdinfo {
    /// File info header.
    pub pfi: proc_fileinfo,
    /// Socket details.
    pub psi: socket_info,
}

/// Resource usage info v4. Size: 296 bytes (verified).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct rusage_info_v4 {
    /// Process UUID.
    pub ri_uuid: [u8; 16],
    /// User time.
    pub ri_user_time: u64,
    /// System time.
    pub ri_system_time: u64,
    /// Package idle wakeups.
    pub ri_pkg_idle_wkups: u64,
    /// Interrupt wakeups.
    pub ri_interrupt_wkups: u64,
    /// Page-ins.
    pub ri_pageins: u64,
    /// Wired memory size.
    pub ri_wired_size: u64,
    /// Resident memory size.
    pub ri_resident_size: u64,
    /// Physical footprint.
    pub ri_phys_footprint: u64,
    /// Process start time (absolute).
    pub ri_proc_start_abstime: u64,
    /// Process exit time (absolute).
    pub ri_proc_exit_abstime: u64,
    /// Child user time.
    pub ri_child_user_time: u64,
    /// Child system time.
    pub ri_child_system_time: u64,
    /// Child package idle wakeups.
    pub ri_child_pkg_idle_wkups: u64,
    /// Child interrupt wakeups.
    pub ri_child_interrupt_wkups: u64,
    /// Child page-ins.
    pub ri_child_pageins: u64,
    /// Child elapsed absolute time.
    pub ri_child_elapsed_abstime: u64,
    /// Disk I/O bytes read.
    pub ri_diskio_bytesread: u64,
    /// Disk I/O bytes written.
    pub ri_diskio_byteswritten: u64,
    /// CPU time at default QoS.
    pub ri_cpu_time_qos_default: u64,
    /// CPU time at maintenance QoS.
    pub ri_cpu_time_qos_maintenance: u64,
    /// CPU time at background QoS.
    pub ri_cpu_time_qos_background: u64,
    /// CPU time at utility QoS.
    pub ri_cpu_time_qos_utility: u64,
    /// CPU time at legacy QoS.
    pub ri_cpu_time_qos_legacy: u64,
    /// CPU time at user-initiated QoS.
    pub ri_cpu_time_qos_user_initiated: u64,
    /// CPU time at user-interactive QoS.
    pub ri_cpu_time_qos_user_interactive: u64,
    /// Billed system time.
    pub ri_billed_system_time: u64,
    /// Serviced system time.
    pub ri_serviced_system_time: u64,
    /// Logical writes.
    pub ri_logical_writes: u64,
    /// Lifetime max physical footprint.
    pub ri_lifetime_max_phys_footprint: u64,
    /// Instructions retired.
    pub ri_instructions: u64,
    /// Cycles consumed.
    pub ri_cycles: u64,
    /// Billed energy (nanojoules).
    pub ri_billed_energy: u64,
    /// Serviced energy (nanojoules).
    pub ri_serviced_energy: u64,
    /// Interval max physical footprint.
    pub ri_interval_max_phys_footprint: u64,
    /// Runnable time.
    pub ri_runnable_time: u64,
}

// ---------------------------------------------------------------------------
// libproc extern functions
// ---------------------------------------------------------------------------

unsafe extern "C" {
    /// Get the executable path for a process.
    pub fn proc_pidpath(pid: c_int, buffer: *mut c_char, buffersize: u32) -> c_int;

    /// List all PIDs on the system.
    pub fn proc_listallpids(buffer: *mut c_void, buffersize: c_int) -> c_int;

    /// Get process info (file descriptor list, task info, etc.).
    pub fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        arg: u64,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;

    /// Get info about a specific file descriptor.
    pub fn proc_pidfdinfo(
        pid: c_int,
        fd: c_int,
        flavor: c_int,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;

    /// Get resource usage for a process.
    pub fn proc_pid_rusage(pid: c_int, flavor: c_int, buffer: *mut c_void) -> c_int;

    /// Get the PID of the app responsible for a helper process.
    pub fn responsibility_get_pid_responsible_for_pid(pid: i32) -> i32;
}

// ---------------------------------------------------------------------------
// Security.framework / CoreFoundation types
// ---------------------------------------------------------------------------

/// Opaque reference to a `SecCode` object.
pub type SecCodeRef = *mut c_void;

/// Opaque reference to a `CFDictionary`.
pub type CFDictionaryRef = *const c_void;

/// Opaque reference to a `CFString`.
pub type CFStringRef = *const c_void;

/// Opaque reference to any Core Foundation object.
pub type CFTypeRef = *const c_void;

/// macOS Security framework status code.
pub type OSStatus = i32;

/// No error.
pub const ERR_SEC_SUCCESS: OSStatus = 0;

/// CFString encoding: UTF-8.
pub const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

/// `kSecCSSigningInformation` flag for `SecCodeCopySigningInformation`.
pub const K_SEC_CS_SIGNING_INFORMATION: u32 = 2;

// ---------------------------------------------------------------------------
// Security.framework extern functions
// ---------------------------------------------------------------------------

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    /// Get a `SecCode` guest by attributes (e.g. audit token → code ref).
    pub fn SecCodeCopyGuestWithAttributes(
        host: SecCodeRef,
        attrs: CFDictionaryRef,
        flags: u32,
        guest: *mut SecCodeRef,
    ) -> OSStatus;

    /// Copy signing information from a code reference.
    pub fn SecCodeCopySigningInformation(
        code: SecCodeRef,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> OSStatus;

    /// Check whether a code reference has a valid signature.
    pub fn SecCodeCheckValidity(
        code: SecCodeRef,
        flags: u32,
        requirement: *const c_void,
    ) -> OSStatus;

    /// Check whether a static code reference has a valid signature.
    ///
    /// Use this instead of `SecCodeCheckValidity` when working with
    /// `SecStaticCode` refs created from `SecStaticCodeCreateWithPath`.
    pub fn SecStaticCodeCheckValidity(
        code: SecCodeRef,
        flags: u32,
        requirement: *const c_void,
    ) -> OSStatus;

    /// Create a `SecCode` from the path of an executable.
    pub fn SecStaticCodeCreateWithPath(
        path: CFTypeRef,
        flags: u32,
        static_code: *mut SecCodeRef,
    ) -> OSStatus;
}

// ---------------------------------------------------------------------------
// Security.framework external symbols
// ---------------------------------------------------------------------------

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    /// Dictionary key for the code signing identifier.
    pub static kSecCodeInfoIdentifier: CFStringRef;

    /// Dictionary key for the team identifier.
    pub static kSecCodeInfoTeamIdentifier: CFStringRef;
}

// ---------------------------------------------------------------------------
// CoreFoundation extern functions
// ---------------------------------------------------------------------------

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    /// Release a Core Foundation object.
    pub fn CFRelease(cf: CFTypeRef);

    /// Get a value from a `CFDictionary` by key.
    pub fn CFDictionaryGetValue(dict: CFDictionaryRef, key: CFTypeRef) -> CFTypeRef;

    /// Create a `CFString` from a C string.
    pub fn CFStringCreateWithCString(
        alloc: *const c_void,
        c_str: *const c_char,
        encoding: u32,
    ) -> CFStringRef;

    /// Copy a `CFString`'s contents into a C buffer.
    pub fn CFStringGetCString(
        string: CFStringRef,
        buffer: *mut c_char,
        buffer_size: isize,
        encoding: u32,
    ) -> bool;

    /// Get the length of a `CFString` in UTF-16 code units.
    pub fn CFStringGetLength(string: CFStringRef) -> isize;

    /// Create a `CFURL` from a file system path.
    pub fn CFURLCreateWithFileSystemPath(
        allocator: *const c_void,
        file_path: CFStringRef,
        path_style: isize,
        is_directory: bool,
    ) -> CFTypeRef;
}

/// `kCFURLPOSIXPathStyle` constant for `CFURLCreateWithFileSystemPath`.
pub const K_CF_URL_POSIX_PATH_STYLE: isize = 0;

// ---------------------------------------------------------------------------
// Size assertions
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "ffi_test.rs"]
mod ffi_test;
