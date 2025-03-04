pub const MAX_PKT_BUFF: usize = 32;
pub const MAX_READ_BUFF: usize = 512;

#[derive(Clone, Debug)]
pub struct Config {
    pub max_buf_packet: usize, /* 当前没用。重组过程中，最多缓存的packet */
}

impl Default for Config {
    fn default() -> Self {
        Config { max_buf_packet: 32 }
    }
}

impl Config {
    pub fn new(heap_capacity: usize) -> Self {
        Config {
            max_buf_packet: heap_capacity,
        }
    }
}
