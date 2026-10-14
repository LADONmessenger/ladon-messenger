use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("E-VERSION: unsupported wire version 0x{0:02x}")]
    UnsupportedVersion(u8),
    #[error("E-MALFORMED: short read — expected {expected} bytes, got {got}")]
    Short { expected: usize, got: usize },
    #[error("E-MALFORMED: trailing bytes after structured payload ({0} extra)")]
    Trailing(usize),
    #[error("E-FETCH-SIG: fetch signature verification failed")]
    FetchSig,
    #[error("E-TOO-LARGE: payload {0} > 16384 B")]
    TooLarge(usize),
    #[error("E-INTERNAL: {0}")]
    Internal(&'static str),
    /// A2 §4: a sealed request or response that does not open or parse.
    #[error("E-MALFORMED: {0}")]
    Malformed(&'static str),
    /// A2 §4: a sealed request addressed to another target.
    #[error("E-WRONG-TARGET: sealed request for another target")]
    WrongTarget,
}

pub type Result<T> = std::result::Result<T, Error>;
