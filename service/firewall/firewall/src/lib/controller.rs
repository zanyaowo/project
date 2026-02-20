use anyhow::Context;
use aya::Ebpf;
use aya::maps::Map;
use aya::programs::{Xdp, XdpFlags};
use aya_log::EbpfLogger;
use log::{warn, info};

pub struct FirewallController{
    bpf: Ebpf
}

impl FirewallController{
    pub fn load(bytecode: &[u8]) -> anyhow::Result<Self>{
        // 修正：移除 expect，直接使用 ? 處理錯誤
        let mut bpf = Ebpf::load(bytecode)?;

        if let Err(e) = EbpfLogger::init(&mut bpf){
            warn!("failed to initialize eBPF logger: {}", e);
        }

        Ok(Self{ bpf })
    }

    pub fn attach(&mut self, iface: &str) -> anyhow::Result<()>{
        let program: &mut Xdp = self.bpf.program_mut("xdp_firewall")
            .context("program not found")?
            .try_into()?;

        program.load().context("failed to load ebpf program")?;
        program.attach(iface, XdpFlags::SKB_MODE).context("failed to attach ebpf program")?;
        Ok(())
    }


    pub fn get_mut_map(&mut self, name: &str) -> Option<&mut Map>{
        self.bpf.map_mut(name)
    }

    pub fn maps_mut(&mut self) -> impl Iterator<Item = (&str, &mut Map)> {
        self.bpf.maps_mut()
    }
}


    