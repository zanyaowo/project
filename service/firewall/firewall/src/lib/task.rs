use aya::maps::{MapData, PerCpuHashMap};
use firewall_common::constants::{IPPROTO_TCP, IPPROTO_UDP};
use firewall_common::session::{SessionKey, SessionValue};
use std::time::SystemTime;

pub fn kill_old_sessions(
    session_table: &mut PerCpuHashMap<&mut MapData, SessionKey, SessionValue>,
) -> i32 {
    let mut count = 0;

    let mut keys_to_remove = Vec::new();

    let current_time_ns = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    for session in session_table.iter() {
        if let Ok((key, value)) = session {
            let proto = key.proto;
            let max_last_seen: u64 = value
                .iter()
                .map(|v| v.last_seen_ts)
                .max()
                .unwrap_or(0 as u64);
            let is_closed = value.iter().any(|v| v.is_close);
            let time_diff_ns = current_time_ns.saturating_sub(max_last_seen as u128);
            let time_diff_sec = time_diff_ns / 1_000_000_000;

            let mut remove = false;

            if proto == IPPROTO_TCP {
                if time_diff_sec > 30 {
                    remove = true;
                } else if is_closed && time_diff_sec > 5 {
                    remove = true;
                }
            } else if proto == IPPROTO_UDP {
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
