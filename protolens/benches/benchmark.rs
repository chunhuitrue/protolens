use criterion::{Criterion, criterion_group, criterion_main};
use protolens::bench::{http, imap, pop3, readline, smtp, task_init, task_new};

fn task_benches(c: &mut Criterion) {
    task_new(c);
    task_init(c);
    readline(c);
    http(c);
    smtp(c);
    pop3(c);
    imap(c);
}

criterion_group!(benches, task_benches);
criterion_main!(benches);
