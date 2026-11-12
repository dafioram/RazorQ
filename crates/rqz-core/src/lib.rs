#![allow(clippy::field_reassign_with_default, clippy::type_complexity)]
//! razerq core: a compression + erasure-coding container that heals itself.

pub mod archive;
pub mod codec;
pub mod crypto;
pub mod error;
pub mod format;
#[cfg(feature = "fs")]
pub mod fsops;
pub mod index;
pub mod progress;
pub mod storage;
pub mod vfs;
pub mod volume;
pub mod writer;

pub use error::{Error, Result};
