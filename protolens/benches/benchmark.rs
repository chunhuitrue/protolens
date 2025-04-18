use criterion::{Criterion, criterion_group, criterion_main};
use protolens::bench::*;

fn task_benches(c: &mut Criterion) {
    task_new(c);
    task_init(c);
    readline100(c);
    readline500(c);
    readline1000(c);
    http(c);
    smtp(c);
    pop3(c);
    imap(c);
}

criterion_group!(benches, task_benches);
criterion_main!(benches);
