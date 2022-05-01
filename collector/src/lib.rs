mod collector;
pub mod descriptor;
pub mod error;
pub mod index;

pub use crate::collector::CollecTor;
use index::Index;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_download_index() {
        let dir = tempfile::tempdir().unwrap();
        let _collector = CollecTor::new(dir.path().to_path_buf()).await.unwrap();
    }
}
