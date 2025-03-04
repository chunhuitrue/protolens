use capture::{CapPacket, Capture};
use flow::{Flow, FlowNode};
use protolens::Prolens;
use std::env;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

mod capture;
mod flow;
mod recognize;

const DP_TIMER_INTERVEL: u128 = 1000; // 1秒

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <pcap_file>", args[0]);
        return;
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    let mut prev_ts = 0;
    let mut cap = Capture::init(&args[1]).unwrap();
    let flow = Flow::new();

    // 一个线程只需要一个protolens实例
    let mut prolens = Prolens::<CapPacket, Rc<CapPacket>>::default();

    while running.load(Ordering::SeqCst) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let diff_ts = now - prev_ts;
        if diff_ts > DP_TIMER_INTERVEL {
            prev_ts = now;
            flow.timer(now);
        }

        let pkt = cap.next_packet(now);
        if pkt.is_none() {
            continue;
        }
        let pkt = pkt.unwrap();
        if pkt.decode().is_err() {
            continue;
        }
        // println!("decode a packet ok! {:?}", pkt);

        // 数据包处理
        let flow_node = flow.process_pkt(&pkt, now, &mut prolens);
        if flow_node.is_none() {
            continue;
        }
        let flow_node = flow_node.unwrap();
        // println!("find a flow node.");

        // 其他flow平级的模块,也需要对node修改
        other_process_pkt(&pkt, &flow_node, now);
    }

    flow.clear();
}

fn other_process_pkt(_pkt: &CapPacket, _node: &FlowNode, _now: u128) {}
