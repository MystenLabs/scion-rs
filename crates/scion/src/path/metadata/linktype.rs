#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, Default)]
pub enum LinkType {
    #[default]
    Invalid = -1,
    Unset = 0,
    Core,
    Parent,
    Child,
    Peer,
}

impl From<i32> for LinkType {
    fn from(value: i32) -> Self {
        match value {
            0 => Self::Unset,
            1 => Self::Core,
            2 => Self::Parent,
            3 => Self::Child,
            4 => Self::Peer,
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
            LinkType::Core,
            LinkType::Parent,
            LinkType::Child,
            LinkType::Peer,
        ] {
            assert_eq!(link_type, LinkType::from(link_type as i32));
        }
    }
}
