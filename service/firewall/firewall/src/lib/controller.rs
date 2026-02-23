use anyhow::Context;
use aya::Ebpf;
use aya::maps::Map;
use aya::maps::Array;
use aya::programs::{Xdp, XdpFlags, tc, SchedClassifier};
use aya_log::EbpfLogger;
use log::warn;

pub struct FirewallController{
    bpf: Ebpf
}

impl FirewallController{
    pub fn load(bytecode: &[u8]) -> anyhow::Result<Self>{
        // 修正：移除 expect，直接使用 ? 處理錯誤
        let mut bpf = Ebpf::load(bytecode)?;
        let mut secret_map = Array::try_from(
            bpf.map_mut("SECRET_KEY").context("SECRET_KEY map not found")?
        )?;
        let secret = rand::random::<u32>();
        secret_map.set(0, secret, 0)?;

        if let Err(e) = EbpfLogger::init(&mut bpf){
            warn!("failed to initialize eBPF logger: {}", e);
        }

        Ok(Self{ bpf })
    }

    pub fn attach_xdp(&mut self, iface: &str) -> anyhow::Result<()>{
        let xdp_program: &mut Xdp = self.bpf.program_mut("xdp_firewall")
            .context("program not found")?
            .try_into()?;

        xdp_program.load().context("failed to load xdp program")?;
        xdp_program.attach(iface, XdpFlags::SKB_MODE).context("failed to attach ebpf program")?;
        Ok(())
    }

    pub fn attach_tc(&mut self , iface: &str) -> anyhow::Result<()>{
        let _ = tc::qdisc_add_clsact(iface);
        let program: &mut SchedClassifier = self.bpf.program_mut("tc_egress")
            .context("tc program not found")?.try_into()?;

        program.load().context("failed to load tc program")?;
        program.attach(iface, aya::programs::TcAttachType::Egress)?;
        Ok(())
    }


    pub fn get_mut_map(&mut self, name: &str) -> Option<&mut Map>{
        self.bpf.map_mut(name)
    }

    pub fn maps_mut(&mut self) -> impl Iterator<Item = (&str, &mut Map)> {
        self.bpf.maps_mut()
    }
}


    