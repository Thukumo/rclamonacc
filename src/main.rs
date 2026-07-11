use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use std::os::fd::AsFd;
use std::{fs, os::fd::BorrowedFd, process, sync::Arc};

use clap::Parser;
use deadpool::managed;
use nix::errno::Errno;
use nix::sys::fanotify::{FanotifyResponse, Response};

use nix::{
    libc,
    sys::fanotify::{EventFFlags, Fanotify, InitFlags, MarkFlags, MaskFlags},
};
use procfs::process::Process;

use tokio::io::unix::AsyncFd;

mod config;
mod job;
mod pool;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = config::Args::parse();
    let config_file = File::open(&args.config).map_err(|e| {
        format!(
            "Failed to open config file '{}': {e}",
            args.config.display(),
        )
    })?;
    let mut cfg: config::Setting = serde_json::from_reader(BufReader::new(config_file))
        .map_err(|e| format!("Failed to parse config file: {e}"))?;

    let pid_content = fs::read_to_string(&cfg.pid_path)
        .map_err(|e| format!("Failed to read clamd PID file '{}': {e}", cfg.pid_path))?;
    let clamd_pid = pid_content
        .trim_end()
        .parse()
        .map_err(|e| format!("Failed to parse PID from '{}': {e}", cfg.pid_path))?;

    cfg.pids.extend([
        // 自分とdaemonのPID
        clamd_pid,
        process::id(),
    ]);

    let cfg = Arc::new(config::Config {
        pids: cfg.pids,
        dirs: cfg
            .directories
            .into_iter()
            .map(std::convert::Into::into)
            .collect(),
        res_on_error: if cfg.deny_on_error {
            Response::FAN_DENY
        } else {
            Response::FAN_ALLOW
        },
        pool: managed::Pool::<pool::StreamManager>::builder(pool::StreamManager::new(
            cfg.socket_path.into(),
        ))
        .max_size(cfg.max_connection)
        .build()?,
    });

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
    for dir in &cfg.dirs {
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
            .filter(|mp| mp.starts_with(dir))
            .for_each(|mp| {
                targets.insert(mp);
            });
    }
    for mp in targets {
        println!("{}", mp.display());
        fanotify.mark(
            MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_MOUNT,
            MaskFlags::FAN_OPEN_PERM,
            unsafe { BorrowedFd::borrow_raw(libc::AT_FDCWD) },
            Some(mp),
        )?;
    }

    let fanotify = Arc::new(AsyncFd::new(fanotify)?);

    loop {
        let mut guard = fanotify.readable().await?;
        match guard.get_inner().read_events() {
            Ok(events) => {
                for event in events.into_iter().filter(|e| e.fd().is_some()) {
                    let cfg = cfg.clone();
                    let pid = event.pid().cast_unsigned();
                    let fanotify = fanotify.clone();

                    tokio::spawn(async move {
                        let fd = event.fd().unwrap();
                        let response = job::job(fd.as_fd(), pid, cfg).await;
                        if let Err(e) = fanotify
                            .get_ref()
                            .write_response(FanotifyResponse::new(fd.as_fd(), response))
                        {
                            eprintln!("{e}");
                        }
                    });
                }
                guard.retain_ready();
            }
            Err(e) if e == Errno::EWOULDBLOCK => {
                guard.clear_ready();
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }
}
