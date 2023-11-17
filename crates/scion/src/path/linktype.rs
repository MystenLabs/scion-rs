use super::{PathParseError, PathParseErrorKind};

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, Default)]
pub enum LinkType {
    #[default]
    Unset = 0,
    Core,
    Parent,
    Child,
    Peer,
}

impl TryFrom<i32> for LinkType {
    type Error = PathParseError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Unset),
            1 => Ok(Self::Core),
            2 => Ok(Self::Parent),
            3 => Ok(Self::Child),
            4 => Ok(Self::Peer),
            _ => Err(PathParseErrorKind::InvalidLinkType.into()),
        }
    }
}
