mod task;

use criterion::{Criterion, criterion_group, criterion_main};

fn task_benches(c: &mut Criterion) {
    task::task_new(c);
    task::parser_new(c);
    task::task_init(c);
}

criterion_group!(benches, task_benches);
criterion_main!(benches);
