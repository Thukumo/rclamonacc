use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use std::os::fd::{AsFd, AsRawFd};
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
    let mut cfg: config::Setting =
        serde_json::from_reader(BufReader::new(File::open(args.config)?))?;

    cfg.pids.extend([
        // 自分とdaemonのPID
        fs::read_to_string(cfg.pid_path)?.trim_end().parse()?,
        process::id(),
    ]);

    let cfg = Arc::new(config::Config {
        pids: cfg.pids,
        dirs: cfg.dirs.into_iter().map(std::convert::Into::into).collect(),
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

    let mountpoints = Process::myself()?
        .mountinfo()?
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
    )?;
    let mut added = HashSet::new();
    for dir in &cfg.dirs {
        let mps = mountpoints
            .iter()
            .filter(|&mp| dir == mp || dir.starts_with(mp) || mp.starts_with(dir));
        for mp in mps {
            if added.insert(mp.clone()) {
                println!("{}", mp.display());
                fanotify.mark(
                    MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_MOUNT,
                    MaskFlags::FAN_OPEN_PERM,
                    unsafe { BorrowedFd::borrow_raw(libc::AT_FDCWD) },
                    Some(mp),
                )?;
            }
        }
    }
    let fanotify = Arc::new(AsyncFd::new(fanotify)?);

    loop {
        let mut guard = fanotify.readable().await?;
        match guard.get_inner().read_events() {
            Ok(events) => {
                for event in events.into_iter().filter(|e| e.fd().is_some()) {
                    let cfg = cfg.clone();
                    let raw_fd = event.fd().unwrap().as_raw_fd();
                    let Ok(fd) = event.fd().unwrap().try_clone_to_owned() else {
                        if let Err(e) = guard.get_inner().write_response(FanotifyResponse::new(
                            event.fd().unwrap(),
                            cfg.res_on_error,
                        )) {
                            eprintln!("{e}");
                        }
                        continue;
                    };
                    let pid = event.pid().cast_unsigned();
                    let fanotify = fanotify.clone();

                    tokio::spawn(async move {
                        if let Err(e) = fanotify.get_ref().write_response(FanotifyResponse::new(
                            unsafe { BorrowedFd::borrow_raw(raw_fd) },
                            job::job(fd.as_fd(), pid, cfg).await,
                        )) {
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
