//! Random-access reading. Everything that only *reads* an archive goes through
//! [`ReadAt`], so the same code runs on files, byte buffers and in the browser.

use std::io;

pub trait ReadAt: Send + Sync {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()>;
    fn len(&self) -> io::Result<u64>;
    fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }
    /// Problems the source already knows about (for example missing volumes).
    fn notes(&self) -> Vec<String> {
        Vec::new()
    }
    /// True when parts of the data are known to be absent. Stops the reader from trusting an
    /// older index checkpoint that would silently describe an earlier state of the archive.
    fn is_incomplete(&self) -> bool {
        false
    }
}

fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "read past end of data")
}

impl ReadAt for Vec<u8> {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(|_| eof())?;
        let end = start.checked_add(buf.len()).ok_or_else(eof)?;
        buf.copy_from_slice(self.get(start..end).ok_or_else(eof)?);
        Ok(())
    }
    fn len(&self) -> io::Result<u64> {
        Ok(self.as_slice().len() as u64)
    }
}

impl<T: ReadAt + ?Sized> ReadAt for &T {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        (**self).read_exact_at(buf, offset)
    }
    fn len(&self) -> io::Result<u64> {
        (**self).len()
    }
    fn notes(&self) -> Vec<String> {
        (**self).notes()
    }
    fn is_incomplete(&self) -> bool {
        (**self).is_incomplete()
    }
}

impl<T: ReadAt + ?Sized> ReadAt for Box<T> {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        (**self).read_exact_at(buf, offset)
    }
    fn len(&self) -> io::Result<u64> {
        (**self).len()
    }
    fn notes(&self) -> Vec<String> {
        (**self).notes()
    }
    fn is_incomplete(&self) -> bool {
        (**self).is_incomplete()
    }
}

impl<T: ReadAt + ?Sized> ReadAt for std::sync::Arc<T> {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        (**self).read_exact_at(buf, offset)
    }
    fn len(&self) -> io::Result<u64> {
        (**self).len()
    }
    fn notes(&self) -> Vec<String> {
        (**self).notes()
    }
    fn is_incomplete(&self) -> bool {
        (**self).is_incomplete()
    }
}

impl ReadAt for std::fs::File {
    #[cfg(unix)]
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        std::os::unix::fs::FileExt::read_exact_at(self, buf, offset)
    }
    #[cfg(windows)]
    fn read_exact_at(&self, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
        use std::os::windows::fs::FileExt;
        while !buf.is_empty() {
            let n = self.seek_read(buf, offset)?;
            if n == 0 {
                return Err(eof());
            }
            buf = &mut buf[n..];
            offset += n as u64;
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    fn read_exact_at(&self, _buf: &mut [u8], _offset: u64) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "files are not available on this platform"))
    }
    fn len(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }
}

pub fn read_vec<S: ReadAt + ?Sized>(s: &S, offset: u64, len: usize) -> io::Result<Vec<u8>> {
    let mut v = vec![0u8; len];
    s.read_exact_at(&mut v, offset)?;
    Ok(v)
}

/// Run `f` over `items`, in parallel when the `parallel` feature is on.
#[cfg(feature = "parallel")]
pub fn pmap<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync + Send) -> Vec<R> {
    use rayon::prelude::*;
    items.par_iter().map(f).collect()
}
#[cfg(not(feature = "parallel"))]
pub fn pmap<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync + Send) -> Vec<R> {
    items.iter().map(f).collect()
}

pub fn parallelism() -> usize {
    #[cfg(feature = "parallel")]
    {
        rayon::current_num_threads()
    }
    #[cfg(not(feature = "parallel"))]
    {
        1
    }
}
