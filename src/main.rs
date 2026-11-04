use std::fs::File;
use std::os::fd::FromRawFd;
use std::process::ExitCode;

use ferrisftp::cli::{self, Action, USAGE};
use ferrisftp::policy::request_names;
use ferrisftp::{Server, log_error, log_info};

fn main() -> ExitCode {
    let opts = match cli::parse(std::env::args_os().skip(1)) {
        Ok(Action::Run(opts)) => opts,
        Ok(Action::Help) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Ok(Action::Version) => {
            println!("ferriSFTP {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Ok(Action::ListRequests) => {
            for name in request_names() {
                println!("{name}");
            }
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("ferrisftp: {e}\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    ferrisftp::log::init(opts.log);
    let session = session_description();
    log_info!("session opened for {session}");

    if let Some(mask) = opts.umask {
        // SAFETY: umask has no failure modes.
        unsafe { libc::umask(mask as libc::mode_t) };
    }
    if let Some(template) = &opts.start_dir {
        // Like OpenSSH's sftp-server, a start directory that cannot be
        // entered is reported but does not end the session.
        match cli::expand_start_dir(template) {
            Ok(dir) => {
                if let Err(e) = std::env::set_current_dir(&dir) {
                    log_error!("cannot change to start directory {}: {e}", dir.display());
                }
            }
            Err(e) => log_error!("start directory: {e}"),
        }
    }

    let mut server = Server::with_policy(opts.policy);
    // Use the raw descriptors: std's stdout is line-buffered and would
    // flush at every newline byte in file data. run() does its own
    // buffering.
    // SAFETY: fds 0 and 1 are open for the life of the process and nothing
    // else in this program uses them.
    let (stdin, stdout) = unsafe { (File::from_raw_fd(0), File::from_raw_fd(1)) };
    let result = server.run(stdin, stdout);
    if let Err(e) = &result {
        log_error!("session ended with error: {e}");
    }
    log_info!("session closed for {session}");
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// "local user NAME from [ADDRESS]", with the address taken from the
/// environment the SSH server sets up (both Dropbear and OpenSSH set
/// SSH_CONNECTION and SSH_CLIENT).
fn session_description() -> String {
    // SAFETY: getuid has no failure modes.
    let uid = unsafe { libc::getuid() };
    let user = ferrisftp::sys::passwd_by_uid(uid).map_or_else(|| uid.to_string(), |p| p.name);
    let addr = ["SSH_CONNECTION", "SSH_CLIENT"]
        .iter()
        .find_map(|var| {
            let value = std::env::var(var).ok()?;
            value.split_whitespace().next().map(str::to_owned)
        })
        .unwrap_or_else(|| "UNKNOWN".into());
    format!("local user {user} from [{addr}]")
}
