use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("not a razerq archive (no valid header found)")]
    NotArchive,
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("corrupt: {0}")]
    Corrupt(String),
    #[error("this archive is encrypted: a password is required")]
    PasswordRequired,
    #[error("wrong password")]
    WrongPassword,
    #[error("block {0} is damaged beyond repair")]
    BlockLost(u64),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
