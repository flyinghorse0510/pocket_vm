use std::process::ExitCode;

fn main() -> ExitCode {
    match pocket_init::run() {
        Ok(never) => match never {},
        Err(error) => {
            eprintln!("pocket-init: {error}");
            if nix::unistd::getpid().as_raw() == 1 {
                pocket_init::emergency_poweroff();
            }
            ExitCode::FAILURE
        }
    }
}
