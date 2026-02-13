use aya_ebpf::{
    macros::map,
    maps::HashMap,
};

#[map]
static mut BLOCK_LIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

pub fn is_blocked(ip: u32) -> bool {
    unsafe {
        BLOCK_LIST.get(&ip).is_some()
    }
}

