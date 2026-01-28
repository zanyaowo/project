#![no_std]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PacketLog{
    pub ip_addr: u32,
    pub len: u32,
    pub action: u32,
}
