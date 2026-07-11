use std::path::PathBuf;

use deadpool::managed;
use tokio::{io::Interest, net::UnixStream};

pub struct StreamManager {
    path: PathBuf,
}

impl StreamManager {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
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
