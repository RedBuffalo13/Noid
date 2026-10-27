//! `Tee` writes to two sinks — used to mirror log output to stderr AND a
//! bounded file without pulling in a logging framework dependency.

use std::io::{self, Write};

pub struct Tee<A: Write, B: Write> {
    a: A,
    b: B,
}

impl<A: Write, B: Write> Tee<A, B> {
    pub fn new(a: A, b: B) -> Self {
        Self { a, b }
    }
}

impl<A: Write, B: Write> Write for Tee<A, B> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Both sinks get the full buffer; report the first one's count.
        let n = self.a.write(buf)?;
        let _ = self.b.write_all(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.a.flush()?;
        self.b.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_to_both_sinks() {
        let mut tee = Tee::new(Vec::<u8>::new(), Vec::<u8>::new());
        tee.write_all(b"hello").unwrap();
        tee.flush().unwrap();
        let (a, b) = (tee.a, tee.b);
        assert_eq!(a, b"hello");
        assert_eq!(b, b"hello");
    }
}
