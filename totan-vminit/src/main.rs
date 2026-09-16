//! Init wrapper for the apple/container VM init image.
//!
//! The init image installs this binary as `/sbin/vminitd` and keeps the stock
//! init at `/sbin/vminitd.real`. At VM boot the wrapper forks. The parent
//! immediately execs the stock init with the same argv and environment, so the
//! VM boots exactly as it does without the wrapper. The child waits for the
//! guest's cgroup v2 hierarchy — totan's cgroup hooks attach to it — and for
//! the loopback interface, which totan's 127.0.0.1 and [::1] listeners bind,
//! and then becomes totan. Progress is written to `/dev/kmsg`, which
//! `container logs --boot` shows.

use std::ffi::CString;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::time::{Duration, Instant};

const VMINITD_REAL: &str = "/sbin/vminitd.real";
const TOTAN_BIN: &str = "/usr/local/bin/totan";
const TOTAN_CONFIG: &str = "/etc/totan/config.toml";
const CGROUP_MOUNTPOINT: &str = "/sys/fs/cgroup";
const LOOPBACK_FLAGS: &str = "/sys/class/net/lo/flags";
/// Deadline shared by every wait below, measured from the fork.
const WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

fn main() {
    // SAFETY: the process is still single-threaded, so the child inherits a
    // consistent heap and holds no locks taken by another thread.
    match unsafe { libc::fork() } {
        -1 => kmsg(&format!(
            "fork failed: {}; booting without totan",
            std::io::Error::last_os_error()
        )),
        0 => start_totan(),
        pid => kmsg(&format!("forked totan starter, pid {pid}")),
    }

    let argv: Vec<CString> = std::env::args_os()
        .map(|arg| cstring(arg.as_bytes()))
        .collect();
    exec(VMINITD_REAL, &argv)
}

/// Wait for cgroup v2 and the loopback interface, then become totan.
fn start_totan() -> ! {
    // SAFETY: no arguments; detaches the child from the boot console session.
    unsafe { libc::setsid() };

    let started = Instant::now();
    wait_for(
        &format!("{CGROUP_MOUNTPOINT} cgroup2 mount"),
        is_cgroup2,
        started,
    );
    wait_for("loopback interface", is_loopback_up, started);

    kmsg(&format!("exec {TOTAN_BIN} --config {TOTAN_CONFIG}"));
    let argv = [
        cstring(TOTAN_BIN.as_bytes()),
        cstring(b"--config"),
        cstring(TOTAN_CONFIG.as_bytes()),
    ];
    exec(TOTAN_BIN, &argv)
}

/// Poll `ready` until it holds, or until [`WAIT_TIMEOUT`] has passed since
/// `started`. Either outcome is reported to `/dev/kmsg`; a timeout is not
/// fatal, because totan may still come up once the guest catches up.
fn wait_for(subject: &str, ready: fn() -> bool, started: Instant) {
    while !ready() {
        if started.elapsed() >= WAIT_TIMEOUT {
            kmsg(&format!(
                "{subject} not ready after {} s; starting totan anyway",
                WAIT_TIMEOUT.as_secs()
            ));
            return;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    kmsg(&format!(
        "{subject} ready after {} ms",
        started.elapsed().as_millis()
    ));
}

fn is_cgroup2() -> bool {
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
        return false;
    };
    mounts.lines().any(|line| {
        let mut fields = line.split_whitespace().skip(1);
        fields.next() == Some(CGROUP_MOUNTPOINT) && fields.next() == Some("cgroup2")
    })
}

/// `lo` reports `operstate` as `unknown` whether it is up or down, so read
/// IFF_UP out of the interface flags instead.
fn is_loopback_up() -> bool {
    let Ok(flags) = std::fs::read_to_string(LOOPBACK_FLAGS) else {
        return false;
    };
    let Some(hex) = flags.trim().strip_prefix("0x") else {
        return false;
    };
    u32::from_str_radix(hex, 16).is_ok_and(|flags| flags & libc::IFF_UP as u32 != 0)
}

fn exec(path: &str, argv: &[CString]) -> ! {
    let program = cstring(path.as_bytes());
    let mut pointers: Vec<*const libc::c_char> = argv.iter().map(|arg| arg.as_ptr()).collect();
    pointers.push(std::ptr::null());
    // SAFETY: `program` and the strings behind `pointers` outlive the call and
    // the pointer array is NULL-terminated. execv keeps the current environ.
    unsafe { libc::execv(program.as_ptr(), pointers.as_ptr()) };
    kmsg(&format!(
        "exec {path} failed: {}",
        std::io::Error::last_os_error()
    ));
    std::process::exit(1)
}

fn cstring(bytes: &[u8]) -> CString {
    CString::new(bytes).expect("exec arguments never contain a NUL byte")
}

fn kmsg(message: &str) {
    if let Ok(mut kmsg) = std::fs::OpenOptions::new().write(true).open("/dev/kmsg") {
        // The kernel turns every write into one log record, so the whole line
        // has to reach it in a single call.
        let _ = kmsg.write_all(format!("<6>totan-vminit: {message}\n").as_bytes());
    }
}
