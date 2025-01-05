mod config;
// mod ffi;
mod packet;
mod parser;
mod pktstrm;
mod pool;
mod task;
#[cfg(test)]
mod test_utils;
mod util;

pub use config::*;
pub use packet::*;
pub use parser::*;
pub use pktstrm::*;
pub use pool::*;
pub use task::*;
pub use util::*;

use std::marker::PhantomData;
use std::sync::Arc;

pub struct ProtoLens<P> {
    config: Config,
    pool: Pool,
    _phantom: PhantomData<P>,
}

impl<P: Packet + Ord + std::fmt::Debug + 'static> ProtoLens<P> {
    pub fn new(config: &Config) -> Self {
        ProtoLens {
            config: config.clone(),
            pool: Pool::new(config.pool_size),
            _phantom: PhantomData,
        }
    }

    pub fn new_task(&self) -> PoolBox<Task<P>> {
        self.pool.acquire(|| Task::new())
    }

    pub fn new_parser<T: Parser<PacketType = P>>(&self) -> PoolBox<T> {
        self.pool.acquire(|| {
            let mut parser = T::new();
            parser.set_pool(Arc::new(self.pool.clone()));
            parser
        })
    }

    pub fn new_task_with_parser<T: Parser<PacketType = P>>(
        &self,
        parser: PoolBox<T>,
    ) -> PoolBox<Task<P>> {
        self.pool.acquire(|| Task::new_with_parser(parser))
    }

    pub fn config(&self) -> &Config {
        &self.config
    }
}

impl<P: Packet + Ord + std::fmt::Debug + 'static> Default for ProtoLens<P> {
    fn default() -> Self {
        let config = Config::default();
        Self::new(&config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::smtp::SmtpParser;
    use crate::test_utils::MyPacket;
    use crate::PktDirection;

    #[test]
    fn test_protolens_basic() {
        let protolens = ProtoLens::<MyPacket>::default();
        let mut task = protolens.new_task();

        let pkt = MyPacket::new(1, false);
        task.run(pkt, PktDirection::Client2Server);
    }

    #[test]
    fn test_protolens_with_parser() {
        let protolens = ProtoLens::<MyPacket>::default();
        let parser = protolens.new_parser::<SmtpParser<MyPacket>>();
        let mut task = protolens.new_task_with_parser(parser);

        let pkt = MyPacket::new(1, false);
        task.run(pkt, PktDirection::Client2Server);
    }

    #[test]
    fn test_protolens_config() {
        let config = Config { pool_size: 20 };
        let protolens = ProtoLens::<MyPacket>::new(&config);

        assert_eq!(protolens.config.pool_size, 20);
    }

    #[test]
    fn test_protolens_multiple_tasks() {
        let protolens = ProtoLens::<MyPacket>::default();

        let mut task1 = protolens.new_task();
        let mut task2 = protolens.new_task();

        let pkt1 = MyPacket::new(1, false);
        let pkt2 = MyPacket::new(2, false);

        task1.run(pkt1, PktDirection::Client2Server);
        task2.run(pkt2, PktDirection::Server2Client);
    }

    #[test]
    fn test_protolens_parser() {
        let protolens = ProtoLens::<MyPacket>::default();
        let parser = protolens.new_parser::<SmtpParser<MyPacket>>();
        let mut task = protolens.new_task_with_parser(parser);

        let pkt = MyPacket::new(1, false);
        task.run(pkt, PktDirection::Client2Server);
    }
}
