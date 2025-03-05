pub const MAX_PKT_BUFF: usize = if cfg!(feature = "pkt_buff_1024") {
    1024
} else if cfg!(feature = "pkt_buff_512") {
    512
} else if cfg!(feature = "pkt_buff_256") {
    256
} else {
    128
};

pub const MAX_READ_BUFF: usize = 512;

#[derive(Clone, Debug, Default)]
pub struct Config {}

impl Config {
    pub fn new() -> Self {
        Config {}
    }
}
