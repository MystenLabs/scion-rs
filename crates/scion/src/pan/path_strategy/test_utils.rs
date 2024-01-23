use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use chrono::{DateTime, Utc};
use scion_proto::{
    address::IsdAsn,
    packet::ByEndpoint,
    path::{Path, PathInterface, PathMetadata},
};

/// Checks that two unordered lists of *test* paths are equal.
///
/// To do this, this macro sorts the paths then compares them for equality. As [`Path`] does not
/// implement `Ord`, paths generated for the tests store a unique ID in the source AS. They are
/// then sorted based on this unique ID for comparison.
macro_rules! assert_paths_unordered_eq {
    ($lhs:expr, $rhs:expr) => {
        let mut lhs: Vec<_> = $lhs.into_iter().collect();
        let mut rhs: Vec<_> = $rhs.into_iter().collect();

        lhs.sort_by_key(Path::source);
        rhs.sort_by_key(Path::source);

        assert_eq!(lhs, rhs);
    };
}

macro_rules! param_test {
    ($func_name:ident -> $return_type:ty: [
        $( $case_name:ident: ( $($arg:expr),* ) ),*
    ]) => {
        mod $func_name {
            use super::*;

            $(
                #[test]
                fn $case_name() -> $return_type {
                    $func_name($($arg),*)
                }
            )*
        }
    };
    ($func_name:ident: [
        $( $case_name:ident: ( $($arg:expr),* ) ),*
    ]) => {
        param_test!($func_name -> (): [ $($case_name: ($($arg),*)),* ]);
    };
    ($func_name:ident$( -> $result:ty)?: [
        $( $case_name:ident: $arg:expr ),*
    ]) => {
        param_test!($func_name$( -> $result)?: [ $($case_name: ($arg)),* ]);
    };
}

pub(crate) use assert_paths_unordered_eq;
pub(crate) use param_test;

/// Returns several paths to the requested destination, all with an expiry time
/// with at most the provided time.
///
/// The paths have the expiry time of expiry_time, then 1 minute earlier for each additional path.
pub(crate) fn get_paths_with_expiry_time_before(
    destination: IsdAsn,
    count: usize,
    expiry_time: DateTime<Utc>,
) -> Vec<Path> {
    (0..count)
        .map(|i| {
            expiry_time
                .checked_sub_signed(chrono::Duration::seconds(60 * i as i64))
                .unwrap_or(DateTime::<Utc>::MIN_UTC)
        })
        .map(|expiration| make_test_path(destination, 1, expiration))
        .collect()
}

pub(crate) fn get_unexpired_paths(destination: IsdAsn, count: usize) -> Vec<Path> {
    (0..count)
        .map(|_| make_test_path(destination, 1, DateTime::<Utc>::MAX_UTC))
        .collect()
}

pub(crate) fn get_paths_with_hops_and_expiry(
    remote_ia: IsdAsn,
    base_expiry_time: DateTime<Utc>,
    hops_and_expiry_offsets: &[(usize, &[Duration])],
) -> Vec<Path> {
    hops_and_expiry_offsets
        .iter()
        .flat_map(|(count, offsets)| {
            offsets
                .iter()
                .map(|offset| make_test_path(remote_ia, *count, base_expiry_time + *offset))
        })
        .collect()
}

pub(crate) fn make_test_path(
    destination: IsdAsn,
    hop_count: usize,
    expiration: DateTime<Utc>,
) -> Path {
    static COUNTER: AtomicU64 = AtomicU64::new(0x99_ff00_0000_f999);

    let source = IsdAsn(COUNTER.fetch_add(1, Ordering::Relaxed));
    let metadata = PathMetadata {
        expiration,
        interfaces: vec![
            Some(PathInterface {
                isd_asn: source,
                id: 1,
            });
            hop_count
        ],
        ..PathMetadata::default()
    };
    Path {
        metadata: Some(metadata),
        ..Path::empty(ByEndpoint {
            source,
            destination,
        })
    }
}
