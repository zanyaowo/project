#![no_std]

// Userspace builds (feature = "user") link against std (aya pulls it in).
// Bring `std` into scope so the cfg-gated IP-address helpers in `session`
// can use `std::net` while the crate stays `no_std` for the eBPF target.
#[cfg(feature = "user")]
extern crate std;

pub mod constants;
pub mod session;

pub mod model;
pub mod protocol;
