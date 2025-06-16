pub(crate) const MAX_PKT_BUFF: usize = 128;
pub(crate) const MAX_READ_BUFF: usize = 2048;

pub(crate) const SMTP_PORT: u16 = 25;
pub(crate) const POP3_PORT: u16 = 110;
pub(crate) const IMAP_PORT: u16 = 143;
pub(crate) const HTTP_PORT: u16 = 80;
pub(crate) const FTP_PORT: u16 = 21;
pub(crate) const SMB_PORT: u16 = 445;

#[derive(Clone, Debug)]
pub struct Config {
    pub pkt_buff: usize,
    pub read_buff: usize,
}

impl Config {
    pub fn new() -> Self {
        Config {
            pkt_buff: 0,
            read_buff: 0,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        let mut conf = Self::new();
        conf.pkt_buff = MAX_PKT_BUFF;
        conf.read_buff = MAX_READ_BUFF;
        conf
    }
}
