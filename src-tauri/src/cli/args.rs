//! A linha de comando. Nomes de comando e de opção em inglês e estáveis; help só em inglês.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "vpnconnect",
    version,
    about = "Control the OpenFortiVpn Connect VPN session from the terminal",
    long_about = "Control the OpenFortiVpn Connect VPN session from the terminal.\n\n\
        The session lives in the Helper, so the app window and this CLI see and control the same \
        session. Only root and the user logged in at the console can talk to the Helper.\n\n\
        Exit codes: 0 success; 1 refused by the Helper or the gateway; 255 CLI failure (bad \
        argument, Helper unavailable); 130 interrupted (Ctrl-C).",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Print only JSON on stdout, in one line; errors go to stderr as {"error":{"code","message"}}
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Show the VPN session: state, IP, connected since, expiry, DNS and Profile
    #[command(long_about = "Show the VPN session: state, IP, connected since, expiry, DNS servers and \
        suffixes, and the Profile. After a disconnect, shows the reason and the cause (tunnel-dropped, \
        expired).\n\n\
        With --json, prints the Helper's state as-is (state, profile_id, ip, since, expires_at, \
        dns_servers, dns_suffixes, url, reason, cause, cert_digest; only the fields of the current \
        state) plus \"profile\": {\"id\", \"name\"}, or null when no session is active. \"name\" is \
        null when the Profile no longer exists on this Mac.")]
    Status,
}
