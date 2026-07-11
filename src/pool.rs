use std::path::PathBuf;

use deadpool::managed;
use tokio::net::UnixStream;

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
        let mut buf = [0; 1];
        match obj.try_read(&mut buf) {
            Ok(0) => Err(managed::RecycleError::Backend(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "Connection closed",
            ))),
            Ok(_) => Err(managed::RecycleError::Backend(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Unexpected data in stream",
            ))),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => match obj.take_error() {
                Ok(None) => Ok(()),
                Ok(Some(err)) | Err(err) => Err(managed::RecycleError::Backend(err)),
            },
            Err(e) => Err(managed::RecycleError::Backend(e)),
        }
    }
}
