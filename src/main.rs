use std::io::{self, IoSlice};
use std::os::fd::AsRawFd;
use std::{fs, os::fd::BorrowedFd, path::PathBuf, process, sync::Arc};

use deadpool::managed;
use nix::errno::Errno;
use nix::sys::{
    fanotify::{FanotifyResponse, Response},
    socket::{ControlMessage, MsgFlags, sendmsg},
};
use nix::{
    libc,
    sys::fanotify::{EventFFlags, Fanotify, InitFlags, MarkFlags, MaskFlags},
};
use procfs::process::Process;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::{
    io::{Interest, unix::AsyncFd},
    net::UnixStream,
};

struct StreamManager {
    path: PathBuf,
}

impl managed::Manager for StreamManager {
    type Type = UnixStream;
    type Error = std::io::Error;
    async fn create(&self) -> Result<Self::Type, Self::Error> {
        UnixStream::connect(&self.path).await
    }
    async fn recycle(
        &self,
        obj: &mut Self::Type,
        _metrics: &managed::Metrics,
    ) -> managed::RecycleResult<Self::Error> {
        match obj.ready(Interest::READABLE | Interest::WRITABLE).await {
            Ok(readiness) => {
                if readiness.is_readable() {
                    // 普通読めない
                    return match obj.try_read(&mut [0; 1]) {
                        Ok(0) => Err(managed::RecycleError::Backend(std::io::Error::new(
                            std::io::ErrorKind::ConnectionReset,
                            "Connection closed",
                        ))),
                        Ok(_) => {
                            // なんか残ってる
                            Err(managed::RecycleError::Backend(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "",
                            )))
                        }
                        Err(e) => Err(managed::RecycleError::Backend(e)),
                    };
                }
                if readiness.is_writable() {
                    Ok(())
                } else {
                    Err(managed::RecycleError::Backend(std::io::Error::new(
                        std::io::ErrorKind::NotConnected,
                        "Connection is not writable",
                    )))
                }
            }
            Err(e) => Err(managed::RecycleError::Backend(e)),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // RH系だと違ったりするらしい
    let socket_path = "/run/clamav/clamd.ctl";
    let pid_path = "/run/clamav/clamd.pid";
    let max_connection = 20;
    let dirs = vec![PathBuf::from("/home")];
    let deny_on_error = false;

    let res_on_error = if deny_on_error {
        Response::FAN_DENY
    } else {
        Response::FAN_ALLOW
    };

    // 自分とdaemonのPID
    let pids = [
        fs::read_to_string(pid_path)?.trim_end().parse()?,
        process::id(),
    ];

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
    for dir in &dirs {
        let mp = mountpoints
            .iter()
            .filter(|mp| dir == *mp || dir.starts_with(mp))
            .max_by_key(|mp| mp.as_os_str().len())
            .unwrap();
        println!("{}", mp.display());
        fanotify.mark(
            MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_MOUNT,
            MaskFlags::FAN_OPEN_PERM,
            unsafe { BorrowedFd::borrow_raw(libc::AT_FDCWD) },
            Some(mp),
        )?;
    }
    let fanotify = AsyncFd::new(fanotify)?;

    let pool =
        managed::Pool::<StreamManager>::builder(StreamManager {
            path: PathBuf::from(socket_path),
        })
        .max_size(max_connection)
        .build()?;

    // todo キャッシュの検討

    loop {
        let mut guard = fanotify.readable().await?;
        match guard.get_inner().read_events() {
            Ok(events) => {
                for event in events.iter().filter(|e| e.fd().is_some()) {
                    let fd = event.fd().unwrap();
                    guard.get_inner().write_response(FanotifyResponse::new(
                        fd,
                        if pids.iter().any(|pid| pid == &(event.pid() as u32)) {
                            Response::FAN_ALLOW
                        } else {
                            if let Ok(file_path) =
                                fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
                            {
                                println!("{}", file_path.display());
                                if !dirs.iter().any(|dir| file_path.starts_with(dir)) {
                                    Response::FAN_ALLOW
                                } else {
                                    if let Ok(mut conn) = pool.get().await {
                                        if let Err(err) = send_fildes(&mut conn, fd).await {
                                            eprintln!("Failed to send fd: {:?}", err);
                                            res_on_error
                                        } else {
                                            match read_response(&mut conn).await {
                                                Ok(resp) => {
                                                    println!(
                                                        "Scan result for {:?}: {}",
                                                        file_path, resp
                                                    );
                                                    if resp.ends_with("OK") {
                                                        Response::FAN_ALLOW
                                                    } else {
                                                        if resp.ends_with("FOUND") {
                                                            Response::FAN_DENY
                                                        } else {
                                                            if deny_on_error {
                                                                Response::FAN_DENY
                                                            } else {
                                                                Response::FAN_ALLOW
                                                            }
                                                        }
                                                    }
                                                }
                                                Err(err) => {
                                                    eprintln!("Failed to read response: {:?}", err);
                                                    res_on_error
                                                }
                                            }
                                        }
                                    } else {
                                        res_on_error
                                    }
                                }
                            } else {
                                res_on_error
                            }
                        },
                    ))?;
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

async fn send_fildes(
    stream: &mut tokio::net::UnixStream,
    fd_to_scan: BorrowedFd<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let iov = [IoSlice::new(&[0u8; 1])];
    let fd = [fd_to_scan.as_raw_fd()];
    let cmsg = [ControlMessage::ScmRights(&fd)];
    stream.writable().await?;

    stream.write_all(b"zFILDES\0").await?;
    stream.flush().await?;

    stream.try_io(tokio::io::Interest::WRITABLE, || {
        sendmsg::<()>(stream.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)
            .map_err(|e| io::Error::other(e.to_string()))
    })?;

    Ok(())
}

async fn read_response(
    stream: &mut tokio::net::UnixStream,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut buf = Vec::new();
    let mut temp = [0u8; 128];
    while buf.last() != Some(&0) {
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&temp[..n]);
    }
    let s = String::from_utf8_lossy(&buf);
    Ok(s.trim_end_matches('\0').to_string())
}
