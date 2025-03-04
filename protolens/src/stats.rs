pub(crate) struct Stats {
    pub(crate) packet_count: usize,
}

impl Stats {
    pub(crate) fn new() -> Self {
        Stats { packet_count: 0 }
    }
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}
