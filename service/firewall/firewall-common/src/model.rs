// define feature index count
pub const FEAT_PROTOCOL: u32 = 0;
pub const FEAT_PACKET_LEN_MEAN: u32 = 1;
pub const FEAT_FWD_MAX: u32 = 2;
pub const FEAT_SYM_RATIO: u32 = 3;
pub const FEAT_PACKET_CV: u32 = 4;

//
pub const FEATURE_COUNT: u32 = 0x05;
pub const FEATURE_COUNT_USIZE: usize = FEATURE_COUNT as usize;
pub const BUCKET_COUNT: u32 = 0x02;
pub const SCORE_TABLE_SIZE: u32 = 32;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct QuantileBound {
    pub value: u64,
    pub numer: u64,
    pub denom: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for QuantileBound {}
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ModelConfig {
    pub enabled: u32,
    pub feature_count: u32,
    pub threshold: i32,
    pub action: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ModelConfig {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ScoreResult {
    pub score: i32,
    pub action: u32,
}

/// flags bit: sample passed kernel BENIGN gate (score*2 < threshold).
/// Only flagged samples feed the reference sketch (S_ref).
pub const STATS_FLAG_BENIGN_GATE: u32 = 0x01;

/// Ring buffer event: raw feature values for sampled flows.
/// Consumed by boundary_updater. numer[i]/denom[i] approximates the ratio
/// value for feature i. `flags` decides whether the sample is eligible for
/// the reference sketch (S_ref) or only the live sketch (S_live).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct StatsEvent {
    pub numer: [u32; FEATURE_COUNT_USIZE],
    pub denom: [u32; FEATURE_COUNT_USIZE],
    pub score: i32,
    pub flags: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for StatsEvent {}

/// Versioned metadata for double-buffered boundary banks.
/// `active` selects which bank of QUANTILE_BOUNDS the datapath reads
/// (bank base offset = active * FEATURE_COUNT). Userspace writes the
/// inactive bank then flips `active` atomically (single set).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct BoundaryMeta {
    pub version: u32,
    pub active: u32,
    pub expiry_ns: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BoundaryMeta {}
