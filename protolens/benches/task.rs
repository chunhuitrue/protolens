use criterion::{Criterion, Throughput, black_box};
use protolens::{Direction, L7Proto, Packet, Prolens, TransProto};
use std::rc::Rc;

pub fn task_new(c: &mut Criterion) {
    let protolens = Prolens::<BenchPacket, Rc<BenchPacket>>::default();

    let mut group = c.benchmark_group("task_new");
    group.throughput(Throughput::Elements(1));
    group.bench_function("task_new", |b| b.iter(|| black_box(protolens.new_task())));
    group.finish();
}

pub fn parser_new(c: &mut Criterion) {
    let protolens = Prolens::<BenchPacket, Rc<BenchPacket>>::default();

    let mut group = c.benchmark_group("parser_new");
    group.throughput(Throughput::Elements(1));
    group.bench_function("parser_new", |b| {
        b.iter(|| {
            if let Some(factory) = black_box(protolens.get_parser_factory(L7Proto::Http)) {
                black_box(factory.create(&protolens));
            }
        })
    });
    group.finish();
}

pub fn task_init(c: &mut Criterion) {
    let protolens = Prolens::<BenchPacket, Rc<BenchPacket>>::default();

    let mut group = c.benchmark_group("task_init");
    group.throughput(Throughput::Elements(1));
    group.bench_function("task_init", |b| {
        b.iter(|| {
            let mut task = black_box(protolens.new_task());

            if let Some(factory) = black_box(protolens.get_parser_factory(L7Proto::Http)) {
                let parser = factory.create(&protolens);
                task.init_parser(parser);
            }
        })
    });
    group.finish();
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct BenchPacket;

impl Packet for BenchPacket {
    fn seq(&self) -> u32 {
        0
    }
    fn tu_sport(&self) -> u16 {
        0
    }
    fn tu_dport(&self) -> u16 {
        0
    }
    fn syn(&self) -> bool {
        false
    }
    fn fin(&self) -> bool {
        false
    }
    fn payload(&self) -> &[u8] {
        &[]
    }
    fn payload_len(&self) -> usize {
        0
    }
    fn trans_proto(&self) -> TransProto {
        TransProto::Tcp
    }
    fn l7_proto(&self) -> L7Proto {
        L7Proto::Unknown
    }
    fn direction(&self) -> Direction {
        Direction::C2s
    }
}
