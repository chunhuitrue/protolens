#[derive(Clone)]
pub struct Config {
    pub pool_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config { pool_size: 10 }
    }
}

impl Config {
    pub fn new(poolsize: usize) -> Self {
        Config {
            pool_size: poolsize,
        }
    }
}
