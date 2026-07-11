use std::path::PathBuf;

use deadpool::managed::Pool;
use nix::sys::fanotify::Response;
use serde::Deserialize;

use crate::pool;

#[derive(Deserialize)]
pub struct Setting {
    #[serde(default = "socket_path")]
    pub socket_path: String,
    #[serde(default = "pid_path")]
    pub pid_path: String,
    #[serde(default = "max_connection")]
    pub max_connection: usize,
    pub dirs: Vec<String>,
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
    pub dirs: Vec<PathBuf>,
    pub res_on_error: Response,
    pub pool: Pool<pool::StreamManager>,
}
