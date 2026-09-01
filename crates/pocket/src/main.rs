use std::process::ExitCode;

fn main() -> ExitCode {
    pocket::main_entry(std::env::args_os())
}
