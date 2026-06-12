use aya_ebpf::{macros::map, maps::HashMap};

use firewall_common::constants::BLOCK_LIST_SIZE;

// Key is the 16-byte IPv6 form (IPv4 flows use the IPv4-mapped address),
// matching SessionKey so a single blocklist serves both stacks.
#[map]
static BLOCK_LIST: HashMap<[u8; 16], u32> = HashMap::with_max_entries(BLOCK_LIST_SIZE, 0);

pub fn is_blocked(ip: [u8; 16]) -> bool {
    unsafe { BLOCK_LIST.get(&ip).is_some() }
}
