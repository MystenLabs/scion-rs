//! A path strategy that periodically refreshes cached paths.

use std::{
    cmp::{self, Reverse},
    collections::HashMap,
    slice,
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use scion_proto::{
    address::IsdAsn,
    path::{Path, PathFingerprint},
};

use super::{utc_instant::UtcInstant, PathFetchError, PathStrategy, Request};

/// A [`PathStrategy`] that queries and refreshes paths.
///
/// A `PathRefresher` is a path strategy that periodically requests path lookups to the configured
/// destination, caches them, and refreshes them as they approach their expiration.
///
/// This strategy is agnostic to failures of its lookup requests. While it has at least one path nearing
/// expiration (within [`QUERY_LEAD_TIME`][Self::QUERY_LEAD_TIME] of its expiration time), it will
/// continuously create requests for path lookups every [`MIN_REFRESH_INTERVAL`][Self::MIN_REFRESH_INTERVAL].
///
/// The path strategy returns paths sorted first in ascending order of their number of interface hops,
/// followed by descending order of their expiration times. The minimum validity of returned paths can be
/// controlled with [`set_min_path_validity`][Self::set_min_path_validity].
///
/// This strategy requires that the stored paths have their associated
/// [`PathMetadata`][scion_proto::path::PathMetadata].
pub struct PathRefresher {
    remote_ia: IsdAsn,
    paths: SortedPaths,
    start: UtcInstant,
    last_query: Option<Instant>,
    min_path_validity: Duration,
}

impl PathRefresher {
    /// The time before a path expires, at which new paths are queried (120 s).
    pub const QUERY_LEAD_TIME: Duration = Duration::from_secs(120);
    /// The minimum time between successive path requests (10 s).
    pub const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(10);
    /// The periodicity with which paths are refreshed (300 s).
    pub const REFRESH_INTERVAL: Duration = Duration::from_secs(300);
    /// The default period before a path's expiration time, at which it is considered expired (5 s).
    pub const DEFAULT_MIN_PATH_VALIDITY: Duration = Duration::from_secs(5);

    /// Creates a new instance of `PathRefresher` for the SCION AS.
    ///
    /// # Panics
    ///
    /// This method panics if `remote_ia` is a wildcard [`IsdAsn`].
    pub fn new(remote_ia: IsdAsn) -> Self {
        assert!(
            !remote_ia.is_wildcard(),
            "cannot create a PathRefresher for a wildcard AS"
        );
        Self {
            remote_ia,
            start: UtcInstant::now(),
            last_query: None,
            paths: SortedPaths::default(),
            min_path_validity: Self::DEFAULT_MIN_PATH_VALIDITY,
        }
    }

    /// The remote SCION AS for which this strategy caches paths.
    pub const fn remote_ia(&self) -> IsdAsn {
        self.remote_ia
    }

    /// Caches paths to the remote SCION AS.
    ///
    /// Only the paths which have a destination of [`remote_ia()`][Self::remote_ia], have associated
    /// metadata, and have not yet expired are cached. All other paths are discarded.
    ///
    /// Cached paths can be retrieved with [`get_path()`][Self::get_path] or [`paths()`][Self::paths].
    pub fn cache_paths(&mut self, paths: &[Path], now: DateTime<Utc>) {
        self.paths.extend_and_remove_expired(
            paths.iter().filter(|p| p.destination() == self.remote_ia),
            now,
        );
    }

    /// Returns the path with the lowest hop count and longest remaining validity.
    pub fn get_path(&self, now: DateTime<Utc>) -> Option<&Path> {
        self.paths.get_best_path(now, self.min_path_validity())
    }

    /// Returns an iterator over the cached, unexpired paths.
    pub fn paths(&self, now: DateTime<Utc>) -> PathsTo<'_> {
        PathsTo::new(&self.paths, now, self.min_path_validity())
    }

    /// Gets the configured minimum path validity.
    ///
    /// See [`set_min_path_validity`][Self::set_min_path_validity] for more information.
    pub const fn min_path_validity(&self) -> Duration {
        self.min_path_validity
    }

    /// Sets the minimum path validity.
    ///
    /// A minimum path validity of `t` ensures that all returned paths will be valid for a duration of
    /// at least `t` from the time the path query is requested. If set to zero, a path may be returned up
    /// until its expiry time.
    ///
    /// A value that is too low (milliseconds or zero) may result in paths being rejected by routers,
    /// as they may expire while traversing the network or be considered expired due differences in time
    /// synchronisation. A value that is too large underutilises the available paths. The default value
    /// of [`DEFAULT_MIN_PATH_VALIDITY`][`Self::DEFAULT_MIN_PATH_VALIDITY`] therefore sets this to a few
    /// seconds.
    pub fn set_min_path_validity(&mut self, offset: Duration) {
        self.min_path_validity = offset;
    }

    #[inline]
    fn check_destination(&self, destination: IsdAsn) -> Result<(), PathFetchError> {
        if destination != self.remote_ia() {
            Err(PathFetchError::UnsupportedDestination)
        } else {
            Ok(())
        }
    }

    /// Duration until the next path lookup.
    fn duration_until_next_lookup(&self, now: Instant) -> Duration {
        let Some(last_query) = self.last_query else {
            return Duration::ZERO;
        };

        let desired_query_in = if self.paths.is_empty() {
            Duration::ZERO
        } else {
            let utc_now = self.start.instant_to_utc(now);

            // Time from now to the next planned query or zero
            let periodic = (last_query + Self::REFRESH_INTERVAL).duration_since(now);

            // Time until the next path expires
            let earliest_expiry = self
                .paths
                .earliest_expiry()
                .expect("there are paths, therefore an earliest expiry time");

            let duration_until_earliest_expiry = earliest_expiry
                .signed_duration_since(utc_now)
                .to_std()
                .unwrap_or(Duration::ZERO);

            let duration_until_refresh = duration_until_earliest_expiry
                .checked_sub(Self::QUERY_LEAD_TIME)
                .unwrap_or(Duration::ZERO);

            cmp::min(duration_until_refresh, periodic)
        };

        let earliest_possible_in = Self::MIN_REFRESH_INTERVAL
            .checked_sub(now.duration_since(last_query))
            .unwrap_or(Duration::ZERO);

        cmp::max(desired_query_in, earliest_possible_in)
    }
}

impl PathStrategy for PathRefresher {
    type PathsTo<'p>
        = PathsTo<'p>
    where
        Self: 'p;

    fn paths_to(
        &self,
        destination: IsdAsn,
        now: Instant,
    ) -> Result<Self::PathsTo<'_>, PathFetchError> {
        self.check_destination(destination)?;

        Ok(self.paths(self.start.instant_to_utc(now)))
    }

    fn path_to(&self, destination: IsdAsn, now: Instant) -> Result<Option<&Path>, PathFetchError> {
        self.check_destination(destination)?;

        Ok(self.get_path(self.start.instant_to_utc(now)))
    }

    fn is_path_available(&self, destination: IsdAsn, now: Instant) -> Result<bool, PathFetchError> {
        Ok(self.path_to(destination, now)?.is_some())
    }

    fn poll_requests(&mut self, now: Instant) -> Request {
        let until_next_lookup = self.duration_until_next_lookup(now);

        if until_next_lookup.is_zero() {
            self.last_query = Some(now);
            Request::LookupPathsTo(self.remote_ia)
        } else {
            Request::Callback(until_next_lookup)
        }
    }

    fn handle_lookup_paths(&mut self, paths: &[Path], now: Instant) {
        self.cache_paths(paths, self.start.instant_to_utc(now));
    }
}

#[derive(Debug)]
struct PathInfo {
    n_interfaces: usize,
    expiry_time: DateTime<Utc>,
    fingerprint: PathFingerprint,
}

impl PathInfo {
    fn new(path: &Path) -> Option<Self> {
        let metadata = path.metadata.as_ref()?;

        Some(Self {
            n_interfaces: metadata.interfaces.len(),
            expiry_time: metadata.expiration,
            fingerprint: path.fingerprint().ok()?,
        })
    }

    fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expiry_time <= now
    }
}

#[derive(Debug, Default)]
struct SortedPaths {
    paths: HashMap<PathFingerprint, Path>,
    path_order: Vec<PathInfo>,
    earliest_expiry: Option<DateTime<Utc>>,
}

impl SortedPaths {
    fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    fn earliest_expiry(&self) -> Option<DateTime<Utc>> {
        self.earliest_expiry
    }

    fn set_earliest_expiry_time(&mut self) {
        self.earliest_expiry = self.path_order.iter().map(|p| p.expiry_time).min()
    }

    fn create_ordering(&mut self) {
        self.path_order.clear();
        self.path_order.extend(
            self.paths
                .values()
                .map(|path| PathInfo::new(path).expect("all stored paths have metadata")),
        );
        self.path_order
            .sort_by_key(|info| (info.n_interfaces, Reverse(info.expiry_time)));
    }

    /// Returns the first path satisfying `expiry_time > now + min_validity`.
    fn get_best_path(&self, now: DateTime<Utc>, min_validity: Duration) -> Option<&Path> {
        self.path_order
            .iter()
            .find(|info| !info.is_expired(now + min_validity))
            .map(|info| &self.paths[&info.fingerprint])
    }

    fn extend_and_remove_expired<'a, T>(&mut self, iter: T, now: DateTime<Utc>)
    where
        T: IntoIterator<Item = &'a Path>,
    {
        for path in iter {
            // We do not store paths without an expiry or expired paths.
            if path.is_expired(now).unwrap_or(true) {
                tracing::debug!(?path, "discarding expired path");
                continue;
            }
            let expiry_time = path
                .expiry_time()
                .expect("paths without expiry time filtered above");

            let Ok(fingerprint) = path.fingerprint() else {
                // We cannot store paths that do not have a fingerprint.
                tracing::debug!("discarding path without a fingerprint");
                continue;
            };

            self.paths
                .entry(fingerprint)
                .and_modify(|prior_path| {
                    let prior_expiry_time = prior_path
                        .expiry_time()
                        .expect("only paths with expiry times to have been stored");

                    if expiry_time > prior_expiry_time {
                        *prior_path = path.clone();
                    }
                })
                .or_insert_with(|| path.clone());
        }

        self.remove_expired(now);
        self.create_ordering();
        self.set_earliest_expiry_time();
    }

    fn remove_expired(&mut self, now: DateTime<Utc>) {
        self.paths.retain(|_, path| {
            !path
                .is_expired(now)
                .expect("only paths with expiry times to have been stored")
        })
    }
}

/// Iterator over SCION paths to a pre-specified destination.
///
/// Created using [`PathStrategy::paths_to`] on a [`PathRefresher`].
#[derive(Default)]
pub struct PathsTo<'a> {
    now: DateTime<Utc>,
    inner: slice::Iter<'a, PathInfo>,
    paths: Option<&'a SortedPaths>,
}

impl<'a> PathsTo<'a> {
    fn new(paths: &'a SortedPaths, now: DateTime<Utc>, min_validity: Duration) -> Self {
        Self {
            paths: Some(paths),
            now: now + min_validity,
            inner: paths.path_order.iter(),
        }
    }
}

impl<'a> Iterator for PathsTo<'a> {
    type Item = &'a Path;

    fn next(&mut self) -> Option<Self::Item> {
        let paths = self.paths?;

        #[allow(clippy::while_let_on_iterator)]
        while let Some(info) = self.inner.next() {
            if !info.is_expired(self.now) {
                return Some(&paths.paths[&info.fingerprint]);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use scion_proto::{address::IsdAsn, path::Path};

    use super::*;
    use crate::pan::path_strategy::{
        test_utils::{
            assert_paths_unordered_eq,
            get_paths_with_expiry_time_before,
            get_paths_with_hops_and_expiry,
            get_unexpired_paths,
            make_test_path,
            param_test,
        },
        utc_instant::UtcInstant,
        Request,
    };

    const REMOTE_IA: IsdAsn = IsdAsn(0x1_ff00_0000_0001);
    const OTHER_IA: IsdAsn = IsdAsn(0x2_ff00_0000_0002);

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
    type GetPathsFn = fn(&PathRefresher, IsdAsn, Instant) -> Result<Vec<Path>, PathFetchError>;

    #[inline]
    fn nanos(nanoseconds: u64) -> Duration {
        Duration::from_nanos(nanoseconds)
    }

    #[inline]
    fn secs(seconds: u64) -> Duration {
        Duration::from_secs(seconds)
    }

    #[inline]
    fn mins(minutes: u64) -> Duration {
        Duration::from_secs(minutes * 60)
    }

    fn get_strategy() -> PathRefresher {
        PathRefresher::new(REMOTE_IA)
    }

    fn get_strategy_with_reference_time() -> (PathRefresher, UtcInstant) {
        let strategy = PathRefresher::new(REMOTE_IA);
        let utc_instant = strategy.start;

        (strategy, utc_instant)
    }

    fn get_multiple_paths_to(
        strategy: &PathRefresher,
        destination: IsdAsn,
        now: Instant,
    ) -> Result<Vec<Path>, PathFetchError> {
        strategy
            .paths_to(destination, now)
            .map(|iter| iter.cloned().collect())
    }

    fn get_single_path_to(
        strategy: &PathRefresher,
        destination: IsdAsn,
        now: Instant,
    ) -> Result<Vec<Path>, PathFetchError> {
        strategy
            .path_to(destination, now)
            .map(|maybe_path| maybe_path.into_iter().cloned().collect())
    }

    // --------------------------------------------------------------------------------
    //   TESTS
    // --------------------------------------------------------------------------------

    fn stores_and_returns_paths(n_paths: usize, get_paths: GetPathsFn) -> TestResult {
        let mut strategy = get_strategy();
        let paths = get_unexpired_paths(strategy.remote_ia(), n_paths);

        strategy.handle_lookup_paths(&paths, Instant::now());
        let returned_paths = get_paths(&strategy, strategy.remote_ia(), Instant::now())?;

        assert_paths_unordered_eq!(returned_paths, paths);

        Ok(())
    }

    param_test! {
        stores_and_returns_paths -> TestResult: [
            path_to: (1, get_single_path_to),
            paths_to_single: (1, get_multiple_paths_to),
            paths_to_multiple: (3, get_multiple_paths_to)
        ]
    }

    fn paths_to_unsupported_ia_errs(unsupported_ia: &str, get_paths: GetPathsFn) {
        let strategy = get_strategy();

        let unsupported_ia: IsdAsn = unsupported_ia.parse().expect("valid ISD-ASN");
        assert_eq!(
            get_paths(&strategy, unsupported_ia, Instant::now()),
            Err(PathFetchError::UnsupportedDestination)
        );
    }

    param_test! {
        paths_to_unsupported_ia_errs -> (): [
            single_path_to_wildcard_isd: ("0-ff00:0:110", get_single_path_to),
            single_path_to_wildcard_asn: ("1-0", get_single_path_to),
            single_path_to_wildcard_ia: ("0-0", get_single_path_to),
            single_path_to_other_ia: (&OTHER_IA.to_string(), get_single_path_to),
            multiple_paths_to_wildcard_isd: ("0-ff00:0:110", get_multiple_paths_to),
            multiple_paths_to_wildcard_asn: ("1-0", get_multiple_paths_to),
            multiple_paths_to_wildcard_ia: ("0-0", get_multiple_paths_to),
            multiple_paths_to_other_ia: (&OTHER_IA.to_string(), get_multiple_paths_to)
        ]
    }

    fn is_path_available_errs_with_unsupported_ia(unsupported_ia: &str) {
        let unsupported_ia: IsdAsn = unsupported_ia.parse().expect("valid ISD-ASN");

        let strategy = get_strategy();
        assert_eq!(
            strategy.is_path_available(unsupported_ia, Instant::now()),
            Err(PathFetchError::UnsupportedDestination),
        );
    }

    param_test! {
        is_path_available_errs_with_unsupported_ia -> (): [
            wildcard_isd: "0-ff00:0:110",
            wildcard_asn: "1-0",
            wildcard_ia: "0-0",
            other_ia: &OTHER_IA.to_string()
        ]
    }

    fn does_not_return_paths_to_other_scion_ases(get_paths: GetPathsFn) {
        let mut strategy = get_strategy();
        let paths = get_unexpired_paths(OTHER_IA, 3);

        strategy.handle_lookup_paths(&paths, Instant::now());

        let returned_paths = get_paths(&strategy, REMOTE_IA, Instant::now())
            .expect("should not err for supported IA");

        assert!(returned_paths.is_empty());
    }

    param_test! {
        does_not_return_paths_to_other_scion_ases -> (): [
            path_to: get_single_path_to,
            paths_to: get_multiple_paths_to
        ]
    }

    fn does_not_return_paths_that_expired_before_storage(get_paths: GetPathsFn) {
        let (mut strategy, start) = get_strategy_with_reference_time();
        let expiry_instant = start.instant() + secs(900);
        let earliest_expiry_time = start.instant_to_utc(expiry_instant);
        let paths =
            get_paths_with_expiry_time_before(strategy.remote_ia(), 3, earliest_expiry_time);

        strategy.handle_lookup_paths(&paths, expiry_instant);

        let returned_paths = get_paths(&strategy, REMOTE_IA, expiry_instant).unwrap();

        assert!(returned_paths.is_empty());
    }

    param_test! {
        does_not_return_paths_that_expired_before_storage -> (): [
            path_to: get_single_path_to,
            paths_to: get_multiple_paths_to
        ]
    }

    fn does_not_return_paths_that_expired_since_storage(get_paths: GetPathsFn) {
        let (mut strategy, start) = get_strategy_with_reference_time();

        let expiry_instant = start.instant() + secs(3600);
        let ten_mins_before_expiry = expiry_instant - secs(60 * 10);

        let earliest_expiry_time = start.instant_to_utc(expiry_instant);
        let paths =
            get_paths_with_expiry_time_before(strategy.remote_ia(), 3, earliest_expiry_time);

        strategy.handle_lookup_paths(&paths, ten_mins_before_expiry);

        let returned_paths = get_paths(&strategy, REMOTE_IA, ten_mins_before_expiry).unwrap();
        assert!(!returned_paths.is_empty());

        let returned_paths = get_paths(&strategy, REMOTE_IA, expiry_instant).unwrap();
        assert!(returned_paths.is_empty());
    }

    param_test! {
        does_not_return_paths_that_expired_since_storage -> (): [
            path_to: get_single_path_to,
            paths_to: get_multiple_paths_to
        ]
    }

    fn panics_if_created_with_wildcard(remote_ia: &str) {
        let remote_ia: IsdAsn = remote_ia.parse().expect("valid IsdAsn");
        assert!(remote_ia.is_wildcard());

        let result = std::panic::catch_unwind(|| {
            PathRefresher::new(remote_ia);
        });
        assert!(result.is_err());
    }

    param_test! {
        panics_if_created_with_wildcard -> (): [
            wildcard_isd: "0-ff00:0:110",
            wildcard_asn: "1-0",
            wildcard_ia: "0-0"
        ]
    }

    #[test]
    fn requests_lookups_if_a_path_is_expired() {
        let (mut strategy, start) = get_strategy_with_reference_time();

        let expiry_instant = start.instant() + secs(3600);
        let expiry_time = start.instant_to_utc(expiry_instant);

        let mut paths = get_paths_with_expiry_time_before(strategy.remote_ia(), 1, expiry_time);
        paths.extend_from_slice(&get_unexpired_paths(strategy.remote_ia(), 2));

        strategy.handle_lookup_paths(&paths, start.instant());

        assert_eq!(
            strategy.poll_requests(expiry_instant),
            Request::LookupPathsTo(strategy.remote_ia())
        );
    }

    #[test]
    fn requests_lookups_if_paths_are_close_to_expiring() {
        let (mut strategy, start) = get_strategy_with_reference_time();
        // Get rid of the initial poll for paths
        strategy.poll_requests(start.instant());

        let expiry_instant = start.instant() + secs(180);
        let expected_refresh_instant = expiry_instant - PathRefresher::QUERY_LEAD_TIME;

        let expiry_time = start.instant_to_utc(expiry_instant);
        let mut paths = get_paths_with_expiry_time_before(strategy.remote_ia(), 1, expiry_time);
        paths.extend_from_slice(&get_unexpired_paths(strategy.remote_ia(), 2));

        strategy.handle_lookup_paths(&paths, start.instant());

        assert_ne!(
            strategy.poll_requests(expected_refresh_instant - nanos(1)),
            Request::LookupPathsTo(strategy.remote_ia()),
            "should not yet request lookup",
        );
        assert_eq!(
            strategy.poll_requests(expected_refresh_instant),
            Request::LookupPathsTo(strategy.remote_ia()),
            "should request lookup at expected refresh instant",
        );
    }

    #[test]
    fn rerequests_lookups_only_after_a_delay() {
        let (mut strategy, start) = get_strategy_with_reference_time();
        // Get rid of the initial poll for paths
        strategy.poll_requests(start.instant());

        let expiry_instant = start.instant() + secs(3600);
        let expected_refresh_instant = expiry_instant - PathRefresher::QUERY_LEAD_TIME;
        let expected_next_refresh_instant =
            expected_refresh_instant + PathRefresher::MIN_REFRESH_INTERVAL;

        let expiry_time = start.instant_to_utc(expiry_instant);
        let mut paths = get_paths_with_expiry_time_before(strategy.remote_ia(), 1, expiry_time);
        paths.extend_from_slice(&get_unexpired_paths(strategy.remote_ia(), 2));

        strategy.handle_lookup_paths(&paths, start.instant());

        assert_eq!(
            strategy.poll_requests(expected_refresh_instant),
            Request::LookupPathsTo(strategy.remote_ia()),
            "should refresh at first expected interval"
        );
        assert_ne!(
            strategy.poll_requests(expected_next_refresh_instant - nanos(1)),
            Request::LookupPathsTo(strategy.remote_ia()),
            "should pause refreshing for MIN_REFRESH_INTERVAL"
        );
        assert_eq!(
            strategy.poll_requests(expected_next_refresh_instant),
            Request::LookupPathsTo(strategy.remote_ia()),
            "should resume refreshing after MIN_REFRESH_INTERVAL"
        );
    }

    #[test]
    fn periodically_refreshes_paths() {
        let (mut strategy, start) = get_strategy_with_reference_time();
        // Get rid of the initial poll for paths
        strategy.poll_requests(start.instant());

        let paths = get_unexpired_paths(strategy.remote_ia(), 3);
        strategy.handle_lookup_paths(&paths, start.instant());

        let expected_refresh_instant = start.instant() + PathRefresher::REFRESH_INTERVAL;

        assert_ne!(
            strategy.poll_requests(expected_refresh_instant - nanos(1)),
            Request::LookupPathsTo(strategy.remote_ia()),
            "should not refresh valid paths before REFRESH_INTERVAL"
        );
        assert_eq!(
            strategy.poll_requests(expected_refresh_instant),
            Request::LookupPathsTo(strategy.remote_ia()),
            "should refresh after REFRESH_INTERVAL"
        );
    }

    fn returns_lowest_hops_least_expired_paths(get_paths: GetPathsFn, truncate_to_first: bool) {
        let (mut strategy, start) = get_strategy_with_reference_time();
        let paths = get_paths_with_hops_and_expiry(
            strategy.remote_ia(),
            start.time(),
            &[(5, &[mins(60), mins(180)]), (2, &[mins(120), mins(30)])],
        );

        strategy.handle_lookup_paths(&paths, start.instant());

        let mut expected_paths: Vec<Path> = [&paths[2], &paths[3], &paths[1], &paths[0]]
            .into_iter()
            .cloned()
            .collect();
        if truncate_to_first {
            expected_paths.truncate(1);
        }

        let returned_paths = get_paths(&strategy, strategy.remote_ia(), start.instant())
            .expect("should return paths");

        assert_eq!(returned_paths, expected_paths);
    }

    param_test! {
        returns_lowest_hops_least_expired_paths -> (): [
            path_to: (get_single_path_to, true),
            paths_to: (get_multiple_paths_to, false)
        ]
    }

    fn returned_paths_respect_min_validity(get_paths: GetPathsFn, min_validity: Duration) {
        let (mut strategy, start) = get_strategy_with_reference_time();
        let expiry_instant = start.instant() + mins(60);
        let min_validity_instant = expiry_instant - min_validity;
        let path = make_test_path(
            strategy.remote_ia(),
            3,
            start.instant_to_utc(expiry_instant),
        );
        strategy.handle_lookup_paths(&[path.clone()], start.instant());

        strategy.set_min_path_validity(min_validity);
        let paths = get_paths(&strategy, strategy.remote_ia(), min_validity_instant).unwrap();
        assert!(
            paths.is_empty(),
            "should not return paths at min validity instant",
        );

        let paths = get_paths(
            &strategy,
            strategy.remote_ia(),
            min_validity_instant - nanos(1),
        )
        .unwrap();
        assert!(
            !paths.is_empty(),
            "should return paths before min validity instant",
        );
    }

    param_test! {
        returned_paths_respect_min_validity -> (): [
            single_path_zero_validity: (get_single_path_to, Duration::ZERO),
            single_path_non_zero_validity: (get_single_path_to, mins(5)),
            multiple_paths_zero_validity: (get_multiple_paths_to, Duration::ZERO),
            multiple_paths_non_zero_validity: (get_multiple_paths_to, mins(5))
        ]
    }

    #[test]
    fn paths_with_newer_expiry_time_replaces_old() {
        let (mut strategy, start) = get_strategy_with_reference_time();

        let mut paths = get_unexpired_paths(strategy.remote_ia(), 2);
        let initial_expiry_time = start.time() + mins(5);
        paths.push(make_test_path(strategy.remote_ia(), 3, initial_expiry_time));

        strategy.handle_lookup_paths(&paths, start.instant());

        // Refresh the path by 60 mins
        paths[2].metadata.as_mut().unwrap().expiration += mins(60);

        strategy.handle_lookup_paths(&paths[2..], start.instant());

        let returned_paths =
            get_multiple_paths_to(&strategy, strategy.remote_ia(), start.instant()).unwrap();

        assert_paths_unordered_eq!(returned_paths, paths);
    }

    #[test]
    fn paths_with_older_expiry_time_are_ignored() {
        let (mut strategy, start) = get_strategy_with_reference_time();

        let mut paths = get_unexpired_paths(strategy.remote_ia(), 2);
        let initial_expiry_time = start.time() + mins(5);
        paths.push(make_test_path(strategy.remote_ia(), 3, initial_expiry_time));

        strategy.handle_lookup_paths(&paths, start.instant());

        // Attempt to refresh with a path with a 1 min earlier expiry time
        let mut older_path = paths[2].clone();
        older_path.metadata.as_mut().unwrap().expiration -= mins(1);

        strategy.handle_lookup_paths(&[older_path], start.instant());

        let returned_paths =
            get_multiple_paths_to(&strategy, strategy.remote_ia(), start.instant()).unwrap();

        assert_paths_unordered_eq!(returned_paths, paths);
    }

    #[test]
    fn looksup_paths_when_empty() {
        let (mut strategy, start) = get_strategy_with_reference_time();

        assert_eq!(
            strategy.poll_requests(start.instant()),
            Request::LookupPathsTo(strategy.remote_ia())
        );
        assert_eq!(
            strategy.poll_requests(start.instant() + PathRefresher::MIN_REFRESH_INTERVAL + secs(1)),
            Request::LookupPathsTo(strategy.remote_ia())
        );
    }
}
