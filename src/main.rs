use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::atomic::AtomicU32;
use std::{fs, os::fd::BorrowedFd, process, sync::Arc};

use clap::Parser;
use nix::errno::Errno;
use nix::sys::fanotify::Response;

use nix::{
    libc,
    sys::fanotify::{EventFFlags, Fanotify, InitFlags, MarkFlags, MaskFlags},
};
use procfs::process::Process;
use tokio::sync::Semaphore;

mod config;
mod job;
mod scan;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = config::Args::parse();
    let config_file = File::open(&args.config).map_err(|e| {
        format!(
            "Failed to open config file '{}': {e}",
            args.config.display(),
        )
    })?;
    let setting: config::Setting = serde_json::from_reader(BufReader::new(config_file))
        .map_err(|e| format!("Failed to parse config file: {e}"))?;

    let pid_path = setting.pid_path;
    let pid_content = fs::read_to_string(&pid_path).map_err(|e| {
        format!(
            "Failed to read clamd PID file '{}': {e}",
            pid_path.display()
        )
    })?;
    let clamd_pid = AtomicU32::new(
        pid_content
            .trim_end()
            .parse::<u32>()
            .map_err(|e| format!("Failed to parse PID from '{}': {e}", pid_path.display()))?,
    );

    let cfg = config::Config {
        uids: setting.exclude_uids,
        my_pid: process::id(),
        clamd_pid,
        dirs: setting.directories,
        ex_dirs: setting.exclude_directories,
        res_on_error: if setting.deny_on_error {
            Response::FAN_DENY
        } else {
            Response::FAN_ALLOW
        },
        semaphore: Semaphore::new(setting.max_connection),
        socket_path: setting.socket_path,
    };

    let mountpoints = Process::myself()
        .map_err(|e| format!("Failed to get current process info: {e}"))?
        .mountinfo()
        .map_err(|e| format!("Failed to read mountinfo: {e}"))?
        .into_iter()
        .filter(|mp| {
            !matches!(
                mp.fs_type.as_str(),
                "proc" | "sysfs" | "devtmpfs" | "cgroup" | "cgroup2" | "pstore"
            )
        })
        .map(|mp| mp.mount_point)
        .collect::<Vec<_>>();

    let fanotify = Fanotify::init(
        InitFlags::FAN_CLASS_CONTENT | InitFlags::FAN_NONBLOCK,
        EventFFlags::O_RDONLY | EventFFlags::O_LARGEFILE,
    )
    .map_err(|e| {
        if e == Errno::EPERM {
            "Permission denied. This program must be run with root privileges (CAP_SYS_ADMIN)."
                .to_string()
        } else {
            format!("Failed to initialize fanotify: {e}")
        }
    })?;
    let mut targets = HashSet::new();
    for dir in cfg.dirs.iter().map(Path::new) {
        // dirより根に近い中で最もdirに近いもの
        if let Some(best_mp) = mountpoints
            .iter()
            .filter(|mp| dir.starts_with(mp))
            .max_by_key(|mp| mp.components().count())
        {
            targets.insert(best_mp);
        }
        // dirの子
        mountpoints
            .iter()
            // dirの子である
            .filter(|mp| mp.starts_with(dir))
            // 除外ディレクトリ, またはその子でない
            .filter(|mp| !cfg.ex_dirs.iter().any(|d| mp.starts_with(d)))
            .for_each(|mp| {
                targets.insert(mp);
            });
    }
    let cfg = Arc::new(cfg);

    for mp in targets {
        println!("{}", mp.display());
        fanotify.mark(
            MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_MOUNT,
            MaskFlags::FAN_OPEN_PERM,
            unsafe { BorrowedFd::borrow_raw(libc::AT_FDCWD) },
            Some(mp),
        )?;
    }
    tokio::select! {
        res = job::event_loop(fanotify, cfg.clone()) => {
            res?;
        },
        res = job::watch_pid_file(pid_path, cfg.clone()) => {
            res?;
        }
    }
    Ok(())
}
