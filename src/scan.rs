use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use std::{
    io::{self, IoSlice},
    os::fd::{AsRawFd as _, BorrowedFd},
    sync::Arc,
};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    net::UnixStream,
};

use crate::config;

async fn send_fildes(
    stream: &mut tokio::net::UnixStream,
    fd_to_scan: std::os::fd::BorrowedFd<'_>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
                .map_err(std::convert::Into::into)
        }) {
            Ok(_) => break,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

async fn read_response(
    stream: &mut tokio::net::UnixStream,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut buf = Vec::new();
    BufReader::new(stream).read_until(b'\0', &mut buf).await?;
    if buf.last() == Some(&0) {
        buf.pop();
    }
    Ok(String::from_utf8(buf)?)
}

pub async fn scan(
    cfg: Arc<config::Config>,
    fd: BorrowedFd<'_>,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut conn = UnixStream::connect(&cfg.socket_path)
        .await
        .map_err(|e| format!("Failed to create connection: {e}"))?;
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        send_fildes(&mut conn, fd),
    )
    .await
    .map_err(|e| format!("Send timeout: {e:?}"))
    .and_then(|inner| inner.map_err(|e| format!("Send Error: {e:?}")))
    .map_err(Box::<dyn std::error::Error>::from)?;

    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), read_response(&mut conn))
        .await
        .map_err(|e| format!("Read timeout: {e:?}"))
        .and_then(|inner| inner.map_err(|e| format!("Read Error: {e:?}")))
        .map_err(Box::<dyn std::error::Error>::from)?;

    Ok(resp)
}
