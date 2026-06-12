use aya::maps::{MapData, PerCpuHashMap};
use firewall_common::constants::{IPPROTO_TCP, IPPROTO_UDP};
use firewall_common::session::{SessionKey, SessionValue};

// Userspace session GC; not scheduled from main() yet (kernel-side LRU covers
// eviction today), kept for the planned maintenance task.
#[allow(dead_code)]
pub fn kill_old_sessions(
    session_table: &mut PerCpuHashMap<&mut MapData, SessionKey, SessionValue>,
) -> i32 {
    let mut count = 0;

    let mut keys_to_remove = Vec::new();

    // bpf_ktime_get_ns() uses CLOCK_BOOTTIME; SystemTime::UNIX_EPOCH would differ
    // by the boot-time offset and cause every session to appear instantly expired.
    let current_time_ns: u128 = unsafe {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts);
        ts.tv_sec as u128 * 1_000_000_000 + ts.tv_nsec as u128
    };

    for (key, value) in session_table.iter().flatten() {
        let proto = key.proto;
        let max_last_seen: u64 = value.iter().map(|v| v.last_seen_ts).max().unwrap_or(0);
        let is_closed = value.iter().any(|v| v.is_close);
        let time_diff_ns = current_time_ns.saturating_sub(max_last_seen as u128);
        let time_diff_sec = time_diff_ns / 1_000_000_000;

        let remove = if proto == IPPROTO_TCP {
            time_diff_sec > 30 || (is_closed && time_diff_sec > 5)
        } else if proto == IPPROTO_UDP {
            time_diff_sec > 10
        } else {
            false
        };

        if remove {
            keys_to_remove.push(key);
        }
    }

    for key in keys_to_remove {
        if session_table.remove(&key).is_ok() {
            count += 1;
        }
    }

    count
}
