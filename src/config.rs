#[derive(Clone, Debug)]
pub struct Config {
    pub pool_size: usize,
    pub heap_capacity: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            pool_size: 10,
            heap_capacity: 32,
        }
    }
}

impl Config {
    pub fn new(poolsize: usize, heap_capacity: usize) -> Self {
        Config {
            pool_size: poolsize,
            heap_capacity,
        }
    }
}
