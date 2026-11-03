//! Command-line options, compatible with OpenSSH's sftp-server so that
//! existing `Subsystem` lines keep working:
//!
//! ```text
//! ferrisftp [-ehR] [-d start_directory] [-f log_facility] [-l log_level]
//!           [-P denied_requests] [-p allowed_requests] [-u umask]
//! ferrisftp -Q requests
//! ```

use std::ffi::OsString;
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use crate::policy::Policy;
use crate::sys;

pub const USAGE: &str = "\
usage: ferrisftp [-ehR] [-d start_directory] [-f log_facility] [-l log_level]
                 [-P denied_requests] [-p allowed_requests] [-u umask]
       ferrisftp -Q requests
       ferrisftp -V

SFTP server meant to be run by an SSH server as its sftp subsystem.
It speaks the SFTP protocol on stdin/stdout.

  -d dir    start in dir instead of the home directory
            (%d = home directory, %u = user name, ~ expands too)
  -e        log to stderr (accepted; logging is not implemented yet)
  -f fac    syslog facility (accepted; logging is not implemented yet)
  -h        show this help
  -l level  log level (accepted; logging is not implemented yet)
  -P list   comma-separated requests to refuse
  -p list   comma-separated requests to allow; all others are refused
  -Q requests
            list the request names usable with -p and -P
  -R        read-only: refuse every request that modifies files
  -u umask  set an explicit umask (octal) for new files and directories
  -V        show version";

#[derive(Debug)]
pub enum Action {
    Run(Options),
    Help,
    Version,
    ListRequests,
}

#[derive(Debug, Default)]
pub struct Options {
    pub policy: Policy,
    pub umask: Option<u32>,
    pub start_dir: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct UsageError(pub String);

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UsageError {}

fn err<T>(msg: impl Into<String>) -> Result<T, UsageError> {
    Err(UsageError(msg.into()))
}

/// Parse arguments (without the program name), getopt style: single-letter
/// options may be bundled (`-eR`) and values may be attached (`-u022`).
pub fn parse<I: IntoIterator<Item = OsString>>(args: I) -> Result<Action, UsageError> {
    let mut opts = Options::default();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let arg = arg
            .into_string()
            .map_err(|a| UsageError(format!("invalid argument {a:?}")))?;
        let Some(flags) = arg.strip_prefix('-').filter(|f| !f.is_empty()) else {
            return err(format!("unexpected argument '{arg}'"));
        };
        for (i, flag) in flags.char_indices() {
            match flag {
                'e' => {}
                'h' => return Ok(Action::Help),
                'V' => return Ok(Action::Version),
                'R' => opts.policy.read_only = true,
                'd' | 'f' | 'l' | 'P' | 'p' | 'Q' | 'u' => {
                    let attached = &flags[i + flag.len_utf8()..];
                    let value = if attached.is_empty() {
                        args.next()
                            .and_then(|v| v.into_string().ok())
                            .ok_or_else(|| UsageError(format!("option -{flag} needs a value")))?
                    } else {
                        attached.to_owned()
                    };
                    match flag {
                        'd' => opts.start_dir = Some(value),
                        // Logging options are validated once logging exists.
                        'f' | 'l' => {}
                        'P' => opts
                            .policy
                            .set_denied(&value)
                            .map_err(|e| UsageError(e.to_string()))?,
                        'p' => opts
                            .policy
                            .set_allowed(&value)
                            .map_err(|e| UsageError(e.to_string()))?,
                        'Q' if value == "requests" => return Ok(Action::ListRequests),
                        'Q' => return err(format!("unknown query '{value}'")),
                        'u' => {
                            let mask = u32::from_str_radix(&value, 8)
                                .ok()
                                .filter(|m| *m <= 0o777)
                                .ok_or_else(|| UsageError(format!("invalid umask '{value}'")))?;
                            opts.umask = Some(mask);
                        }
                        _ => unreachable!(),
                    }
                    break; // the value consumed the rest of this argument
                }
                other => return err(format!("unknown option -{other}")),
            }
        }
    }
    Ok(Action::Run(opts))
}

/// Expand `~`, `~user`, `%d` (home directory), `%u` (user name) and `%%`
/// in a start directory, as OpenSSH's sftp-server does.
pub fn expand_start_dir(template: &str) -> Result<PathBuf, UsageError> {
    // SAFETY: getuid has no failure modes.
    let uid = unsafe { libc::getuid() };
    let me = sys::passwd_by_uid(uid);

    let tilde = sys::expand_tilde(template.as_bytes())
        .ok_or_else(|| UsageError(format!("no such user in '{template}'")))?;
    let mut out = Vec::new();
    let mut bytes = tilde.as_os_str().as_bytes().iter().copied();
    while let Some(b) = bytes.next() {
        if b != b'%' {
            out.push(b);
            continue;
        }
        match bytes.next() {
            Some(b'%') => out.push(b'%'),
            Some(b'd') => {
                let home = me
                    .as_ref()
                    .map(|p| p.home.clone())
                    .or_else(sys::current_home)
                    .ok_or_else(|| UsageError("cannot determine home directory".into()))?;
                out.extend_from_slice(home.as_os_str().as_bytes());
            }
            Some(b'u') => {
                let name = me
                    .as_ref()
                    .ok_or_else(|| UsageError("cannot determine user name".into()))?;
                out.extend_from_slice(name.name.as_bytes());
            }
            Some(other) => return err(format!("unknown escape '%{}'", other as char)),
            None => return err("start directory ends with '%'"),
        }
    }
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(&out)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::*;

    fn run(args: &[&str]) -> Result<Options, UsageError> {
        match parse(args.iter().map(OsString::from))? {
            Action::Run(o) => Ok(o),
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn defaults() {
        let o = run(&[]).unwrap();
        assert!(!o.policy.read_only);
        assert_eq!(o.umask, None);
        assert_eq!(o.start_dir, None);
    }

    #[test]
    fn flags_values_and_bundling() {
        let o = run(&["-eR", "-l", "INFO", "-fAUTH", "-u", "027", "-d/srv/%u"]).unwrap();
        assert!(o.policy.read_only);
        assert_eq!(o.umask, Some(0o027));
        assert_eq!(o.start_dir.as_deref(), Some("/srv/%u"));

        let o = run(&["-P", "remove,rmdir"]).unwrap();
        assert!(!o.policy.permits(SSH_FXP_REMOVE, None));
        let o = run(&["-p", "open,read,close"]).unwrap();
        assert!(!o.policy.permits(SSH_FXP_STAT, None));
    }

    #[test]
    fn actions() {
        let p = |a: &[&str]| parse(a.iter().map(OsString::from)).unwrap();
        assert!(matches!(p(&["-h"]), Action::Help));
        assert!(matches!(p(&["-V"]), Action::Version));
        assert!(matches!(p(&["-Q", "requests"]), Action::ListRequests));
    }

    #[test]
    fn errors() {
        assert!(run(&["-x"]).is_err());
        assert!(run(&["-u"]).is_err());
        assert!(run(&["-u", "999"]).is_err());
        assert!(run(&["-u", "abc"]).is_err());
        assert!(run(&["-P", "remove,frobnicate"]).is_err());
        assert!(run(&["stray"]).is_err());
        assert!(run(&["-"]).is_err());
        assert!(parse(["-Q", "ciphers"].map(OsString::from)).is_err());
    }

    #[test]
    fn start_dir_expansion() {
        let me = sys::passwd_by_uid(unsafe { libc::getuid() }).unwrap();
        assert_eq!(
            expand_start_dir("/srv/%u/x").unwrap(),
            PathBuf::from(format!("/srv/{}/x", me.name))
        );
        assert_eq!(expand_start_dir("%d").unwrap(), me.home);
        assert_eq!(
            expand_start_dir("~/up").unwrap(),
            sys::current_home().unwrap().join("up")
        );
        assert_eq!(expand_start_dir("/a%%b").unwrap(), PathBuf::from("/a%b"));
        assert!(expand_start_dir("/a%x").is_err());
        assert!(expand_start_dir("/a%").is_err());
    }
}
