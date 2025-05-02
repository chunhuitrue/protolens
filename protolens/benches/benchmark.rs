use criterion::{Criterion, criterion_group, criterion_main};
use protolens::bench::*;

fn benches(c: &mut Criterion) {
    task_new(c);
    task_init(c);
    readline100(c);
    readline100_new_task(c);
    readline500(c);
    readline500_new_task(c);
    readline1000(c);
    readline1000_new_task(c);
    http(c);
    http_new_task(c);
    smtp(c);
    smtp_new_task(c);
    pop3(c);
    imap(c);
    sip(c);
}

criterion_group!(normal_benches, benches);
criterion_group!(flame_task, task_init_flame);
criterion_group!(flame_http_new_task, http_new_task_flame);
criterion_main!(normal_benches, flame_task, flame_http_new_task);
