use std::process::ExitCode;

fn main() -> ExitCode {
    match pocket_builder_init::run() {
        Ok(never) => match never {},
        Err(error) => {
            eprintln!("pocket-builder-init: {error}");
            #[cfg(target_os = "linux")]
            if nix::unistd::getpid().as_raw() == 1 {
                pocket_builder_init::emergency_poweroff();
            }
            ExitCode::FAILURE
        }
    }
}
