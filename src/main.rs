use std::fs::File;
use std::os::fd::FromRawFd;
use std::process::ExitCode;

use ferrisftp::Server;
use ferrisftp::cli::{self, Action, USAGE};
use ferrisftp::policy::request_names;

fn main() -> ExitCode {
    let opts = match cli::parse(std::env::args_os().skip(1)) {
        Ok(Action::Run(opts)) => opts,
        Ok(Action::Help) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Ok(Action::Version) => {
            println!("ferrisftp {}", env!("CARGO_PKG_VERSION"));
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
                    eprintln!("ferrisftp: cannot change to {}: {e}", dir.display());
                }
            }
            Err(e) => eprintln!("ferrisftp: start directory: {e}"),
        }
    }

    let mut server = Server::with_policy(opts.policy);
    // Use the raw descriptors: std's stdout is line-buffered and would
    // flush at every newline byte in file data. run() does its own
    // buffering.
    // SAFETY: fds 0 and 1 are open for the life of the process and nothing
    // else in this program uses them.
    let (stdin, stdout) = unsafe { (File::from_raw_fd(0), File::from_raw_fd(1)) };
    match server.run(stdin, stdout) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ferrisftp: {e}");
            ExitCode::FAILURE
        }
    }
}
