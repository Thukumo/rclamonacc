use nix::sys::{
    fanotify::Response,
    socket::{ControlMessage, MsgFlags, sendmsg},
};
use std::{
    io::{self, IoSlice},
    os::fd::{AsRawFd as _, BorrowedFd},
    sync::Arc,
};
use tokio::{
    fs,
    io::{AsyncReadExt as _, AsyncWriteExt as _},
};

use crate::{config, job};

pub async fn send_fildes(
    stream: &mut tokio::net::UnixStream,
    fd_to_scan: std::os::fd::BorrowedFd<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let iov = [IoSlice::new(&[0u8; 1])];
    let fd = [fd_to_scan.as_raw_fd()];
    let cmsg = [ControlMessage::ScmRights(&fd)];
    stream.writable().await?;

    stream.write_all(b"zFILDES\0").await?;
    stream.flush().await?;

    loop {
        stream.writable().await?;
        match stream.try_io(tokio::io::Interest::WRITABLE, || {
            sendmsg::<()>(stream.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)
                .map_err(|e| io::Error::other(e.to_string()))
        }) {
            Ok(_) => break,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

pub async fn read_response(
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

pub async fn job(fd: BorrowedFd<'_>, pid: u32, cfg: Arc<config::Config>) -> Response {
    if cfg.pids.contains(&pid) {
        Response::FAN_ALLOW
    } else if let Ok(file_path) = fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).await {
        println!("{}", file_path.display());
        if cfg.dirs.iter().any(|dir| file_path.starts_with(dir)) {
            if let Ok(mut conn) = cfg.pool.get().await {
                if let Err(err) = job::send_fildes(&mut conn, fd).await {
                    eprintln!("Failed to send fd: {err:?}");
                    cfg.res_on_error
                } else {
                    match job::read_response(&mut conn).await {
                        Ok(resp) => {
                            println!("Scan result for {}: {resp}", file_path.display());
                            if resp.ends_with("OK") {
                                Response::FAN_ALLOW
                            } else if resp.ends_with("FOUND") {
                                Response::FAN_DENY
                            } else {
                                // ERROR
                                cfg.res_on_error
                            }
                        }
                        Err(err) => {
                            eprintln!("Failed to read response: {err:?}");
                            cfg.res_on_error
                        }
                    }
                }
            } else {
                cfg.res_on_error
            }
        } else {
            Response::FAN_ALLOW
        }
    } else {
        cfg.res_on_error
    }
}
