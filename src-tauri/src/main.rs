// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> std::process::ExitCode {
    // Com argumentos é a CLI, decidida antes de qualquer inicialização do Tauri (ADR 0003).
    if app_lib::cli::wants_cli() {
        return app_lib::cli::main();
    }
    app_lib::run();
    std::process::ExitCode::SUCCESS
}
