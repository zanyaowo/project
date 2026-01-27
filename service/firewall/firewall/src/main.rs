<<<<<<< Updated upstream
fn main() {
    println!("Hello, world! for test");
=======
use aya::{include_bytes_aligned, Ebpf};
use aya::maps::RingBuf;
use aya::programs::{Xdp, XdpFlags};
use aya_log::EbpfLogger;
use firewall_common::PacketLog;
use log::{info, warn};
use std::net::Ipv4Addr;
use tokio::io::unix::AsyncFd;
use tokio::signal;
use core::ptr;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(env!("FIREWALL_BPF")))?;

    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(env!("FIREWALL_BPF")))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut Xdp = bpf.program_mut("xdp_firewall").unwrap().try_into()?;
    program.load()?;
    program.attach("wlp3s0", XdpFlags::SKB_MODE).unwrap();

    info!("waiting for ctrl+c");

    let mut events: RingBuf<_> = bpf.map_mut("EVENTS").unwrap().try_into()?;
    let mut poll = AsyncFd::new(events)?;

    loop {
        let mut guard = poll.readable_mut().await?;
        let ring_buf = guard.get_inner_mut();

        // 3. 讀取所有可用的事件
        while let Some(event) = ring_buf.next() {
            let log = unsafe { ptr::read(event.as_ptr() as *const PacketLog) };
            println!(
                "SRC IP: {}, LEN: {}, ACTION: {}",
                Ipv4Addr::from(log.ip_addr),
                log.len,
                log.action
            );
        }
        guard.clear_ready();
    }
>>>>>>> Stashed changes
}
