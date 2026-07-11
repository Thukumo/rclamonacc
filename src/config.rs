use std::{path::PathBuf, sync::atomic::AtomicU32};

use nix::sys::fanotify::Response;
use serde::Deserialize;
use tokio::sync::Semaphore;

#[derive(Deserialize)]
pub struct Setting {
    #[serde(default = "socket_path")]
    pub socket_path: String,
    #[serde(default = "pid_path")]
    pub pid_path: String,
    #[serde(default = "max_connection")]
    pub max_connection: usize,
    pub directories: Vec<String>,
    #[serde(default)]
    pub deny_on_error: bool,
    #[serde(default)]
    pub pids: Vec<u32>,
}

// RH系だと違ったりするらしい
fn socket_path() -> String {
    "/run/clamav/clamd.ctl".into()
}
fn pid_path() -> String {
    "/run/clamav/clamd.pid".into()
}

fn max_connection() -> usize {
    20
}

#[derive(clap::Parser)]
pub struct Args {
    pub config: PathBuf,
}

pub struct Config {
    pub pids: Vec<u32>,
    pub clamd_pid: AtomicU32,
    pub dirs: Vec<String>,
    pub res_on_error: Response,
    pub semaphore: Semaphore,
    pub socket_path: PathBuf,
}
