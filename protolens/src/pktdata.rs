use crate::packet::*;

pub(crate) struct PktData<T>
where
    T: Packet,
{
    pkt: T,
    read_offset: usize,
}

impl<T> PktData<T>
where
    T: Packet,
{
    pub(crate) fn new(pkt: T) -> Self {
        PktData {
            pkt,
            read_offset: 0,
        }
    }

    pub(crate) fn readline(&mut self) -> Result<(&[u8], usize), ()> {
        let payload = self.pkt.payload();
        if self.read_offset >= payload.len() {
            return Err(());
        }

        let offset = self.read_offset;
        let remaining = &payload[self.read_offset..];
        for i in 0..remaining.len() - 1 {
            if remaining[i] == b'\r' && remaining[i + 1] == b'\n' {
                let line = &remaining[..i + 2];
                self.read_offset += i + 2;
                return Ok((line, offset));
            }
        }
        Err(())
    }

    pub(crate) fn readline_str(&mut self) -> Result<(&str, usize), ()> {
        let (bytes, offset) = self.readline()?;
        unsafe { Ok((std::str::from_utf8_unchecked(bytes), offset)) }
    }

    pub(crate) fn readn(&mut self, size: usize) -> Result<(&[u8], usize), ()> {
        let payload = self.pkt.payload();
        if self.read_offset >= payload.len() {
            return Err(());
        }

        let remaining = payload.len() - self.read_offset;
        if size > remaining {
            return Err(());
        }

        let offset = self.read_offset;
        let data = &payload[self.read_offset..self.read_offset + size];
        self.read_offset += size;

        Ok((data, offset))
    }

    pub(crate) fn remain_data(&self) -> bool {
        let payload = self.pkt.payload();
        self.read_offset < payload.len()
    }
}
