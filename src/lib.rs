mod config;
mod ffi;
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

pub struct ProtoLens<T> {
    pool: Pool<T>,
    config: Config,
}

impl<T> ProtoLens<T> {
    pub fn new(config: Config) -> Self {
        ProtoLens {
            pool: Pool::new(config.pool_size),
            config,
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }
}

impl<P: Packet + Ord + std::fmt::Debug + 'static> ProtoLens<Task<P>> {
    pub fn new_task(&self) -> PooledObject<Task<P>> {
        self.pool.acquire(|| Task::new())
    }

    pub fn new_task_with_parser(
        &self,
        parser: impl Parser<PacketType = P>,
    ) -> PooledObject<Task<P>> {
        self.pool.acquire(|| Task::new_with_parser(parser))
    }
}

impl<T> Default for ProtoLens<T> {
    fn default() -> Self {
        Self::new(Config::default())
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
        let protolens = ProtoLens::<Task<MyPacket>>::default();
        let mut task = protolens.new_task();

        let pkt = MyPacket::new(1, false);
        task.run(pkt, PktDirection::Client2Server);
    }

    #[test]
    fn test_protolens_with_parser() {
        let protolens = ProtoLens::<Task<MyPacket>>::default();
        let mut task = protolens.new_task_with_parser(SmtpParser::new());

        let pkt = MyPacket::new(1, false);
        task.run(pkt, PktDirection::Client2Server);
    }
}
