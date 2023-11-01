macro_rules! parse {
    ($string:literal) => {
        $string.parse().unwrap()
    };
}

pub(crate) use parse;
