use criterion::{Criterion, criterion_group, criterion_main};
use protolens::bench::*;

fn benches(c: &mut Criterion) {
    task_new(c);
    task_init(c);
    readline100(c);
    readline500(c);
    readline1000(c);
    http_new_task(c);
    http(c);
    smtp(c);
    pop3(c);
    imap(c);
    sip(c);
}

criterion_group!(normal_benches, benches);
criterion_group!(perf_task, task_init_perf);
criterion_group!(perf_http, http_perf);
criterion_main!(normal_benches, perf_task, perf_http);
