use std::io;
use std::process::ExitCode;

use ferrisftp::Server;

const USAGE: &str = "\
usage: ferrisftp [-h] [-V]

SFTP server meant to be run by an SSH server as its sftp subsystem.
It speaks the SFTP protocol on stdin/stdout.

  -h   show this help
  -V   show version";

fn main() -> ExitCode {
    // Phase 1 has no runtime options yet; any argument ends the program.
    if let Some(arg) = std::env::args().nth(1) {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "-V" | "--version" => {
                println!("ferrisftp {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("ferrisftp: unknown option '{other}'\n{USAGE}");
                return ExitCode::from(2);
            }
        }
    }

    let mut server = Server::new();
    match server.run(io::stdin().lock(), io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ferrisftp: {e}");
            ExitCode::FAILURE
        }
    }
}
