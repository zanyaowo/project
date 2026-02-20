use aya::maps::{MapData, PerCpuHashMap};
use firewall_common::{SessionKey, SessionValue};

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
pub fn kill_old_sessions(session_table: &mut PerCpuHashMap<&mut MapData, SessionKey, SessionValue>) -> i32 {
    let mut count = 0;

    let mut keys_to_remove = Vec::new();

    let current_time_ns = unsafe {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
        (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
    };

    for session in session_table.iter() {
        if let Ok((key, value)) = session {
            let proto = key.proto;
            let max_last_seen: u64 = value.iter().map(|v| v.last_seen_ts).max().unwrap_or(0 as u64);
            let is_closed = value.iter().any(|v| v.is_close);
            let time_diff_ns = current_time_ns.saturating_sub(max_last_seen);
            let time_diff_sec = time_diff_ns / 1_000_000_000;

            let mut remove = false;

            if proto == PROTO_TCP { // TCP
                if time_diff_sec > 30 {
                    remove = true;
                } else if is_closed && time_diff_sec > 5 {
                    remove = true;
                }
            } else if proto == PROTO_UDP { // UDP
                if time_diff_sec > 10 {
                    remove = true;
                }
            }

            if remove {
                keys_to_remove.push(key);
            }
        }
    }

    for key in keys_to_remove {
        if session_table.remove(&key).is_ok() {
            count += 1;
        }
    }

    count
}
