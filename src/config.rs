use std::{
    ffi::OsString,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
    sync::atomic::AtomicU32,
};

use derive_more::{AsRef, Deref};
use nix::sys::fanotify::Response;
use serde::Deserialize;
use tokio::sync::Semaphore;

#[derive(Deref, AsRef)]
pub struct AbsoluteDirPath(
    #[deref(forward)]
    #[as_ref(forward)]
    OsString,
);

impl<'de> Deserialize<'de> for AbsoluteDirPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = OsString::deserialize(deserializer)?;
        let path = Path::new(&s);
        if !path.is_absolute() {
            return Err(serde::de::Error::custom(format!(
                "Path must be absolute: {}",
                s.display()
            )));
        }
        Ok(Self(if s.as_bytes().ends_with(b"/") {
            s
        } else {
            let mut s = s.into_vec();
            s.push(b'/');
            OsString::from_vec(s)
        }))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Setting {
    #[serde(default = "socket_path")]
    pub socket_path: OsString,
    #[serde(default = "pid_path")]
    pub pid_path: OsString,
    #[serde(default = "max_connection")]
    pub max_connection: usize,
    pub directories: Vec<AbsoluteDirPath>,
    #[serde(default)]
    pub exclude_directories: Vec<AbsoluteDirPath>,
    #[serde(default)]
    pub deny_on_error: bool,
    #[serde(default)]
    pub exclude_uids: Vec<u32>,
}

// RH系だと違ったりするらしい
fn socket_path() -> OsString {
    "/run/clamav/clamd.ctl".into()
}
fn pid_path() -> OsString {
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
    pub uids: Vec<u32>,
    pub my_pid: u32,
    pub clamd_pid: AtomicU32,
    pub dirs: Vec<AbsoluteDirPath>,
    pub ex_dirs: Vec<AbsoluteDirPath>,
    pub res_on_error: Response,
    pub semaphore: Semaphore,
    pub socket_path: PathBuf,
}
