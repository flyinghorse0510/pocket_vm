use std::process::ExitCode;

fn main() -> ExitCode {
    match pocket_validator_init::run() {
        Ok(never) => match never {},
        Err(error) => {
            eprintln!("pocket-validator-init: {error}");
            #[cfg(target_os = "linux")]
            if nix::unistd::getpid().as_raw() == 1 {
                pocket_validator_init::emergency_poweroff();
            }
            ExitCode::FAILURE
        }
    }
}
