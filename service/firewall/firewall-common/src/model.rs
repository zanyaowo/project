
// define feature index count
pub const FEAT_PROTOCOL: u32 = 0;
pub const FEAT_PACKET_LEN_MEAN: u32 = 1;
pub const FEAT_SHAPE_RATIO: u32 = 2;
pub const FEAT_SYM_RATIO: u32 = 3;
pub const FEAT_PACKET_CV: u32 = 4;

//
pub const FEATURE_COUNT: u32 = 0x05;
pub const BUCKET_COUNT: u32 = 0x10;
pub const CROSS_MULT_MASK: u32 = 0b11110;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct QuantileBound{
    pub value: u64,
    pub numer: u64,
    pub denom: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ModelWeight{
    pub weight: i32,
    pub padding: [u8; 4]
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ModelConfig{
    pub enabled: u32,
    pub feature_count: u32,
    pub threshold: i32,
    pub action: u32,
}



