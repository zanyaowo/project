use anyhow::Context;
use aya::maps::Array;
use aya::maps::HashMap;
use aya::maps::Map;
use aya::programs::{tc, SchedClassifier, Xdp, XdpFlags};
use aya::Ebpf;
use aya_log::EbpfLogger;
use log::warn;
use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::lib::config::{Config, XdpMode};

pub struct FirewallController {
    bpf: Ebpf,
    config: Arc<Config>,
}

impl FirewallController {
    pub fn load(bytecode: &[u8], config: Arc<Config>) -> anyhow::Result<Self> {
        let mut bpf = Ebpf::load(bytecode)?;

        let mut secret_map = Array::try_from(
            bpf.map_mut("SECRET_KEY")
                .context("SECRET_KEY map not found")?,
        )?;

        // set secret key
        if config.security.enable_random_secret {
            let secret = rand::random::<u32>();
            secret_map.set(0, secret, 0)?;
        } else {
            let secret = config.security.custom_cookie.unwrap_or_else(rand::random);
            secret_map.set(0, secret, 0)?;
        }

        if let Err(e) = EbpfLogger::init(&mut bpf) {
            warn!("failed to initialize eBPF logger: {}", e);
        }

        Ok(Self { bpf, config })
    }

    pub fn attach_xdp(&mut self, iface: &str) -> anyhow::Result<()> {
        let xdp_program: &mut Xdp = self
            .bpf
            .program_mut("xdp_firewall")
            .context("program not found")?
            .try_into()?;

        xdp_program.load().context("failed to load xdp program")?;

        match self.config.network.xdp_mode {
            XdpMode::Native => xdp_program.attach(iface, XdpFlags::DRV_MODE),
            XdpMode::Skb => xdp_program.attach(iface, XdpFlags::SKB_MODE),
        }
        .context("failed to attach ebpf program")?;

        Ok(())
    }

    pub fn attach_tc(&mut self, iface: &str) -> anyhow::Result<()> {
        let _ = tc::qdisc_add_clsact(iface);
        let program: &mut SchedClassifier = self
            .bpf
            .program_mut("tc_egress")
            .context("tc program not found")?
            .try_into()?;

        program.load().context("failed to load tc program")?;
        program.attach(iface, aya::programs::TcAttachType::Egress)?;
        Ok(())
    }

    pub fn detach_tc(&mut self, iface: &str) -> anyhow::Result<()> {
        // detach_program 在 aya 0.13.1 對我們的情境常 fail（program 已隨 Ebpf drop 自動清除），
        // 但 clsact qdisc 不會自動移除 → 殘留 `qdisc clsact ffff:` 影響下次重啟。
        // 直接呼叫 iproute2 的 `tc` 來刪 qdisc，是最簡單可靠的方法。
        let status = std::process::Command::new("tc")
            .args(["qdisc", "del", "dev", iface, "clsact"])
            .status()
            .context("failed to invoke `tc qdisc del`")?;
        if !status.success() {
            log::warn!("`tc qdisc del dev {iface} clsact` exited with {status}");
        }
        Ok(())
    }

    pub fn block_ip(&mut self, ip: Ipv4Addr) -> anyhow::Result<()> {
        let map = self
            .bpf
            .map_mut("BLOCK_LIST")
            .context("BLOCK_LIST not found")?;
        let mut block_map: HashMap<_, u32, u32> = HashMap::try_from(map)?;
        block_map.insert(u32::from(ip), 1u32, 0)?;
        Ok(())
    }

    pub fn unblock_ip(&mut self, ip: Ipv4Addr) -> anyhow::Result<()> {
        let map = self
            .bpf
            .map_mut("BLOCK_LIST")
            .context("BLOCK_LIST not found")?;
        let mut block_map: HashMap<_, u32, u32> = HashMap::try_from(map)?;
        block_map.remove(&u32::from(ip))?;
        Ok(())
    }

    pub fn list_blocked(&mut self) -> anyhow::Result<Vec<Ipv4Addr>> {
        let map = self
            .bpf
            .map_mut("BLOCK_LIST")
            .context("BLOCK_LIST not found")?;
        let block_map: HashMap<_, u32, u32> = HashMap::try_from(map)?;
        let ips = block_map
            .iter()
            .filter_map(|r| r.ok().map(|(ip, _)| Ipv4Addr::from(ip)))
            .collect();
        Ok(ips)
    }

    pub fn get_mut_map(&mut self, name: &str) -> Option<&mut Map> {
        self.bpf.map_mut(name)
    }

    pub fn maps_mut(&mut self) -> impl Iterator<Item = (&str, &mut Map)> {
        self.bpf.maps_mut()
    }
}
