use inotify::{EventMask, Inotify, StreamExt as _, WatchMask};
use nix::{
    errno::Errno,
    libc,
    sys::fanotify::{Fanotify, FanotifyResponse, MarkFlags, MaskFlags, Response},
};
use std::{
    fs,
    os::fd::{AsRawFd as _, BorrowedFd},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::io::unix::AsyncFd;

use crate::{config, scan};

async fn job(fd: BorrowedFd<'_>, cfg: Arc<config::Config>) -> Option<Response> {
    match tokio::time::timeout(std::time::Duration::from_secs(5), cfg.semaphore.acquire()).await {
        Ok(_) => {
            match scan::scan(cfg.clone(), fd).await {
                Ok(resp) => {
                    if resp.ends_with("OK") {
                        Some(Response::FAN_ALLOW)
                    } else if resp.ends_with("FOUND") {
                        // パスが欲しい(LazyCell?)
                        println!("Threat detected: {resp}");
                        Some(Response::FAN_DENY)
                    } else {
                        // ERROR
                        eprintln!("Error Responce: {resp}");
                        None
                    }
                }
                Err(e) => {
                    eprintln!("Failed to scan: {e:?}");
                    None
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to acquire semaphore: {e:?}");
            None
        }
    }
}

pub async fn event_loop(
    fanotify: Fanotify,
    cfg: Arc<config::Config>,
) -> Result<(), Box<dyn std::error::Error>> {
    let fanotify = Arc::new(AsyncFd::new(fanotify)?);

    let mut path = [0u8; 32];
    let mut file_path = [0u8; 4096];

    loop {
        let mut guard = fanotify.readable().await?;
        match guard.get_inner().read_events() {
            Ok(events) => {
                if events.iter().any(|e| e.fd().is_none()) {
                    eprintln!("!! Queue overflowed !!");
                }
                for event in events.into_iter().filter(|e| e.fd().is_some()) {
                    enum Status {
                        Allowed,
                        Ignored,
                        Error,
                        NeedScan,
                    }
                    let res = {
                        let pid = event.pid().cast_unsigned();
                        if cfg.pids.contains(&pid)
                            || pid == cfg.clamd_pid.load(std::sync::atomic::Ordering::Acquire)
                        {
                            Status::Allowed
                        } else {
                            let mut cursor = std::io::Cursor::new(&mut path[..]);
                            // pathのサイズと書き込まれる文字列のデータ長から、panicしなさそう
                            std::io::Write::write_fmt(
                                &mut cursor,
                                format_args!("/proc/self/fd/{}\0", event.fd().unwrap().as_raw_fd()),
                            )
                            .unwrap();

                            let len = unsafe {
                                libc::readlink(
                                    path.as_ptr().cast::<libc::c_char>(),
                                    file_path.as_mut_ptr().cast::<libc::c_char>(),
                                    file_path.len(),
                                )
                            };
                            if len <= 0 {
                                eprintln!(
                                    "Failed to get file path: {:?}",
                                    std::io::Error::last_os_error()
                                );
                                Status::Error
                            } else {
                                let len = len.cast_unsigned();
                                if cfg
                                    .dirs
                                    .iter()
                                    .any(|d| file_path[..len].starts_with(d.as_bytes()))
                                {
                                    Status::NeedScan
                                } else {
                                    Status::Ignored
                                }
                            }
                        }
                    };
                    match res {
                        Status::Allowed => {
                            if let Err(e) = fanotify.get_ref().write_response(
                                FanotifyResponse::new(event.fd().unwrap(), Response::FAN_ALLOW),
                            ) {
                                eprintln!("Failed to write response(early): {e}");
                            }
                        }
                        Status::Error => {
                            if let Err(e) = fanotify.get_ref().write_response(
                                FanotifyResponse::new(event.fd().unwrap(), cfg.res_on_error),
                            ) {
                                eprintln!("Failed to write response(early): {e}");
                            }
                        }
                        Status::Ignored => {
                            if let Err(e) = fanotify.get_ref().write_response(
                                FanotifyResponse::new(event.fd().unwrap(), Response::FAN_ALLOW),
                            ) {
                                eprintln!("Failed to write response(early): {e}");
                            }
                        }
                        Status::NeedScan => {
                            let cfg = cfg.clone();
                            let fanotify = fanotify.clone();

                            tokio::spawn(async move {
                                let fd = event.fd().unwrap();
                                let response = job(fd, cfg.clone()).await;

                                // 次に書き込みがあるまでOPEN_PERMイベントを通知しない
                                let res = if response == Some(Response::FAN_ALLOW) {
                                    fanotify
                                        .get_ref()
                                        .mark(
                                            MarkFlags::FAN_MARK_ADD
                                                | MarkFlags::FAN_MARK_IGNORED_MASK,
                                            MaskFlags::FAN_OPEN_PERM,
                                            fd,
                                            None::<&Path>,
                                        )
                                        .err()
                                } else {
                                    None
                                };

                                if let Err(e) = fanotify.get_ref().write_response(
                                    FanotifyResponse::new(fd, response.unwrap_or(cfg.res_on_error)),
                                ) {
                                    eprintln!("{e}");
                                }

                                if let Some(e) = res {
                                    if e == Errno::ENOSPC {
                                        // IGNOREのしすぎ
                                        if let Err(e) = fanotify.get_ref().mark(
                                            MarkFlags::FAN_MARK_FLUSH,
                                            MaskFlags::empty(),
                                            unsafe { BorrowedFd::borrow_raw(libc::AT_FDCWD) },
                                            None::<&Path>,
                                        ) {
                                            eprintln!("Failed to flush mark: {e}");
                                        }
                                    } else {
                                        eprintln!("Falied to add ignored mask: {e}");
                                    }
                                }
                            });
                        }
                    }
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
