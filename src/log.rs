//! Logging to syslog or stderr, with the levels and facilities of
//! OpenSSH's sftp-server (`-l`, `-f`, `-e`).
//!
//! Until [`init`] is called nothing is logged, so the library stays silent
//! when embedded or under test.

use std::ffi::CString;
use std::fmt;
use std::io::Write;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Quiet,
    Fatal,
    Error,
    Info,
    Verbose,
    Debug1,
    Debug2,
    Debug3,
}

impl Level {
    pub fn parse(s: &str) -> Option<Level> {
        Some(match s.to_ascii_uppercase().as_str() {
            "QUIET" => Level::Quiet,
            "FATAL" => Level::Fatal,
            "ERROR" => Level::Error,
            "INFO" => Level::Info,
            "VERBOSE" => Level::Verbose,
            "DEBUG" | "DEBUG1" => Level::Debug1,
            "DEBUG2" => Level::Debug2,
            "DEBUG3" => Level::Debug3,
            _ => return None,
        })
    }

    fn syslog_priority(self) -> libc::c_int {
        match self {
            Level::Quiet | Level::Fatal => libc::LOG_CRIT,
            Level::Error => libc::LOG_ERR,
            Level::Info | Level::Verbose => libc::LOG_INFO,
            Level::Debug1 | Level::Debug2 | Level::Debug3 => libc::LOG_DEBUG,
        }
    }
}

/// Parse a syslog facility name as accepted by `-f`.
pub fn parse_facility(s: &str) -> Option<libc::c_int> {
    Some(match s.to_ascii_uppercase().as_str() {
        "DAEMON" => libc::LOG_DAEMON,
        "USER" => libc::LOG_USER,
        "AUTH" => libc::LOG_AUTH,
        "AUTHPRIV" => libc::LOG_AUTHPRIV,
        "LOCAL0" => libc::LOG_LOCAL0,
        "LOCAL1" => libc::LOG_LOCAL1,
        "LOCAL2" => libc::LOG_LOCAL2,
        "LOCAL3" => libc::LOG_LOCAL3,
        "LOCAL4" => libc::LOG_LOCAL4,
        "LOCAL5" => libc::LOG_LOCAL5,
        "LOCAL6" => libc::LOG_LOCAL6,
        "LOCAL7" => libc::LOG_LOCAL7,
        _ => return None,
    })
}

#[derive(Debug, Clone, Copy)]
pub struct Config {
    pub level: Level,
    pub facility: libc::c_int,
    pub stderr: bool,
}

impl Default for Config {
    /// OpenSSH's defaults: errors only, to syslog facility AUTH.
    fn default() -> Self {
        Config {
            level: Level::Error,
            facility: libc::LOG_AUTH,
            stderr: false,
        }
    }
}

static CONFIG: OnceLock<Config> = OnceLock::new();

/// Enable logging. Only the first call has an effect.
pub fn init(config: Config) {
    if CONFIG.set(config).is_ok() && !config.stderr && config.level > Level::Quiet {
        // openlog keeps the ident pointer, so it must live forever.
        static IDENT: &std::ffi::CStr = c"ferrisftp";
        // SAFETY: IDENT is a static NUL-terminated string.
        unsafe { libc::openlog(IDENT.as_ptr(), libc::LOG_PID, config.facility) };
    }
}

pub fn enabled(level: Level) -> bool {
    CONFIG
        .get()
        .is_some_and(|c| level <= c.level && c.level > Level::Quiet)
}

#[doc(hidden)]
pub fn write(level: Level, args: fmt::Arguments<'_>) {
    let Some(config) = CONFIG.get() else { return };
    let mut msg = args.to_string();
    if config.stderr {
        msg.push('\n');
        let _ = std::io::stderr().write_all(msg.as_bytes());
        return;
    }
    // Messages are already escaped (see `Quoted`), so a NUL can only come
    // from a bug; drop the message rather than truncate it silently.
    let Ok(cmsg) = CString::new(msg) else { return };
    // SAFETY: a "%s" format with one valid C string argument.
    unsafe { libc::syslog(level.syslog_priority(), c"%s".as_ptr(), cmsg.as_ptr()) };
}

/// Log at a level, only formatting the message if that level is enabled.
#[macro_export]
macro_rules! log_at {
    ($level:expr, $($arg:tt)*) => {
        if $crate::log::enabled($level) {
            $crate::log::write($level, format_args!($($arg)*));
        }
    };
}

#[macro_export]
macro_rules! log_error { ($($arg:tt)*) => { $crate::log_at!($crate::log::Level::Error, $($arg)*) }; }
#[macro_export]
macro_rules! log_info { ($($arg:tt)*) => { $crate::log_at!($crate::log::Level::Info, $($arg)*) }; }
#[macro_export]
macro_rules! log_verbose { ($($arg:tt)*) => { $crate::log_at!($crate::log::Level::Verbose, $($arg)*) }; }
#[macro_export]
macro_rules! log_debug { ($($arg:tt)*) => { $crate::log_at!($crate::log::Level::Debug1, $($arg)*) }; }

/// Displays a client-supplied byte string inside double quotes, escaping
/// control characters, quotes, backslashes and invalid UTF-8, so a crafted
/// file name cannot forge extra log lines.
pub struct Quoted<'a>(pub &'a [u8]);

impl fmt::Display for Quoted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"")?;
        for chunk in self.0.utf8_chunks() {
            for c in chunk.valid().chars() {
                match c {
                    '"' => f.write_str("\\\"")?,
                    '\\' => f.write_str("\\\\")?,
                    c if c.is_control() => write!(f, "\\x{:02x}", c as u32)?,
                    c => write!(f, "{c}")?,
                }
            }
            for b in chunk.invalid() {
                write!(f, "\\x{b:02x}")?;
            }
        }
        f.write_str("\"")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels() {
        assert_eq!(Level::parse("info"), Some(Level::Info));
        assert_eq!(Level::parse("DEBUG"), Some(Level::Debug1));
        assert_eq!(Level::parse("DEBUG3"), Some(Level::Debug3));
        assert_eq!(Level::parse("loud"), None);
        assert!(Level::Error < Level::Info);
        assert_eq!(parse_facility("local7"), Some(libc::LOG_LOCAL7));
        assert_eq!(parse_facility("kern"), None);
    }

    #[test]
    fn quoting() {
        assert_eq!(Quoted(b"plain/path.txt").to_string(), "\"plain/path.txt\"");
        assert_eq!(
            Quoted(b"evil\nInjected line \"x\"\\").to_string(),
            "\"evil\\x0aInjected line \\\"x\\\"\\\\\""
        );
        assert_eq!(Quoted("caf\u{e9}".as_bytes()).to_string(), "\"caf\u{e9}\"");
        assert_eq!(Quoted(b"bad\xffbyte").to_string(), "\"bad\\xffbyte\"");
    }

    #[test]
    fn silent_until_init() {
        // Tests never call init, so nothing is enabled.
        assert!(!enabled(Level::Error));
    }
}
