use crate::address::IsdAsn;

/// Information about the local AS
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct AsInfo {
    pub ia: IsdAsn,
    pub mtu: u16,
}

/// Flags for path requests
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct PathRequestFlags {
    pub refresh: bool,
    pub hidden: bool,
}
