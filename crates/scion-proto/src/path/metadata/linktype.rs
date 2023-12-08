/// The type of an inter-domain link based on the underlay connection.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, Default)]
pub enum LinkType {
    /// Invalid link type
    Invalid = -1,
    /// Unspecified
    #[default]
    Unset = 0,
    /// Direct physical connection.
    Direct,
    /// Connection with local routing/switching.
    MultiHop,
    /// Connection overlaid over publicly routed Internet.
    OpenNet,
}

impl From<i32> for LinkType {
    fn from(value: i32) -> Self {
        match value {
            0 => Self::Unset,
            1 => Self::Direct,
            2 => Self::MultiHop,
            3 => Self::OpenNet,
            _ => Self::Invalid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_values() {
        for link_type in [
            LinkType::Invalid,
            LinkType::Unset,
            LinkType::Direct,
            LinkType::MultiHop,
            LinkType::OpenNet,
        ] {
            assert_eq!(link_type, LinkType::from(link_type as i32));
        }
    }
}
