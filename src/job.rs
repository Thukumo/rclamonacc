use inotify::{EventMask, Inotify, StreamExt as _, WatchMask};
use nix::{
    errno::Errno,
    sys::fanotify::{Fanotify, FanotifyResponse, Response},
};
use std::{
    fs,
    os::fd::{AsFd as _, AsRawFd as _, BorrowedFd},
    path::PathBuf,
    sync::Arc,
};
use tokio::io::unix::AsyncFd;

use crate::{config, job, scan};
async fn job(fd: BorrowedFd<'_>, pid: u32, cfg: Arc<config::Config>) -> Response {
    if cfg.pids.contains(&pid) || pid == cfg.clamd_pid.load(std::sync::atomic::Ordering::Acquire) {
        Response::FAN_ALLOW
    } else {
        match fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())) {
            Ok(file_path) => {
                if cfg.dirs.iter().any(|dir| file_path.starts_with(dir)) {
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        cfg.semaphore.acquire(),
                    )
                    .await
                    {
                        Ok(_) => {
                            match scan::scan(cfg.clone(), fd).await {
                                Ok(resp) => {
                                    if resp.ends_with("OK") {
                                        Response::FAN_ALLOW
                                    } else if resp.ends_with("FOUND") {
                                        println!("Threat detected: {resp}");
                                        Response::FAN_DENY
                                    } else {
                                        // ERROR
                                        eprintln!("Error Responce: {resp}");
                                        cfg.res_on_error
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Failed to scan: {e:?}");
                                    cfg.res_on_error
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to acquire semaphore: {e:?}");
                            cfg.res_on_error
                        }
                    }
                } else {
                    Response::FAN_ALLOW
                }
            }
            Err(e) => {
                eprintln!("Failed to get file path: {e:?}");
                cfg.res_on_error
            }
        }
    }
}

pub async fn event_loop(
    fanotify: Fanotify,
    cfg: Arc<config::Config>,
) -> Result<(), Box<dyn std::error::Error>> {
    let fanotify = Arc::new(AsyncFd::new(fanotify)?);

    loop {
        let mut guard = fanotify.readable().await?;
        match guard.get_inner().read_events() {
            Ok(events) => {
                if events.iter().any(|e| e.fd().is_none()) {
                    eprintln!("!! Queue overflowed !!");
                }
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

pub async fn watch_pid_file(
    path: PathBuf,
    cfg: Arc<config::Config>,
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = path
        .parent()
        .ok_or_else(|| format!("Failed to get parent directory of {}", path.display()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| format!("Failed to get filename of {}", path.display()))?;

    let inotify = Inotify::init().map_err(|e| format!("Failed to init inotify: {e}"))?;
    inotify
        .watches()
        .add(dir, WatchMask::CLOSE_WRITE | WatchMask::CREATE)
        .map_err(|e| format!("Failed to add inotify watch: {e}"))?;
    let mut buf = [0u8; 4096];
    let mut stream = inotify
        .into_event_stream(&mut buf)
        .map_err(|e| format!("Failed to convert inotify into stream: {e}"))?;

    while let Some(ev) = stream.next().await {
        if let Ok(ev) = ev
            && let Some(name) = ev.name
            && name == file_name
            && (ev.mask.contains(EventMask::CLOSE_WRITE) || ev.mask.contains(EventMask::CREATE))
            && let Ok(s) = fs::read_to_string(&path)
            && let Ok(pid) = s.trim_end().parse::<u32>()
        {
            cfg.clamd_pid
                .store(pid, std::sync::atomic::Ordering::Release);
        }
    }

    Ok(())
}
