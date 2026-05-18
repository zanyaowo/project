use anyhow::Context;
use aya::maps::Array;
use aya::maps::Map;
use aya::programs::{tc, SchedClassifier, Xdp, XdpFlags};
use aya::Ebpf;
use aya_log::EbpfLogger;
use log::warn;
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
        if (config.security.enable_random_secret) {
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

    pub fn get_mut_map(&mut self, name: &str) -> Option<&mut Map> {
        self.bpf.map_mut(name)
    }

    pub fn maps_mut(&mut self) -> impl Iterator<Item = (&str, &mut Map)> {
        self.bpf.maps_mut()
    }
}
