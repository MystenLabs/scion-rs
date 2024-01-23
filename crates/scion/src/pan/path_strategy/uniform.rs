//! A uniform path strategy that can be used to compose other strategies.

use std::{
    cell::RefCell,
    cmp,
    collections::{hash_map::Entry, HashMap},
    time::{Duration, Instant},
};

use scion_proto::{address::IsdAsn, path::Path};

use super::{PathFetchError, PathStrategy, Request};

/// A [path strategy][PathStrategy] that applies another path strategy on a per-destination basis.
///
/// Path strategies, such as the [`PathRefresher`][super::refresher::PathRefresher] strategy, are
/// created only for a specific destination SCION AS. The `UniformStrategy` allows extending such
/// strategies to work for multiple destination ASes by creating a new instance of the strategy for
/// each destination.
///
/// A new instance of the strategy is only created for a destination when a path to that destination is
/// requested, or paths to that destination are cached.
pub struct UniformStrategy<T> {
    inner: HashMap<IsdAsn, T>,
    factory: Box<dyn FnMut(IsdAsn) -> T>,
    destinations_to_add: RefCell<Vec<IsdAsn>>,
}

impl<T> UniformStrategy<T>
where
    T: PathStrategy,
{
    /// Creates a new instance of `UniformStrategy` that uses the provided factory function
    /// to initialise new instances of a [`PathStrategy`] for each queried destination.
    pub fn new<F>(factory: F) -> Self
    where
        F: FnMut(IsdAsn) -> T + 'static,
    {
        Self {
            inner: HashMap::new(),
            factory: Box::new(factory),
            destinations_to_add: RefCell::default(),
        }
    }

    fn get_strategy(&self, destination: IsdAsn) -> Result<&T, PathFetchError> {
        if destination.is_wildcard() {
            return Err(PathFetchError::UnsupportedDestination);
        }

        if let Some(strategy) = self.inner.get(&destination) {
            Ok(strategy)
        } else {
            self.destinations_to_add.borrow_mut().push(destination);
            Err(PathFetchError::RequiresPoll)
        }
    }

    fn get_or_insert(&mut self, remote_ia: IsdAsn) -> &mut T {
        assert!(!remote_ia.is_wildcard());
        self.inner
            .entry(remote_ia)
            .or_insert_with(|| (self.factory)(remote_ia))
    }

    fn fill_missing_destinations(&mut self) {
        for remote_ia in self.destinations_to_add.borrow_mut().drain(..) {
            if let Entry::Vacant(entry) = self.inner.entry(remote_ia) {
                entry.insert((self.factory)(remote_ia));
            }
        }
    }
}

impl<T> PathStrategy for UniformStrategy<T>
where
    T: PathStrategy,
{
    type PathsTo<'p> = T::PathsTo<'p>
    where
        Self: 'p;

    fn paths_to(
        &self,
        destination: IsdAsn,
        now: Instant,
    ) -> Result<Self::PathsTo<'_>, PathFetchError> {
        self.get_strategy(destination)?.paths_to(destination, now)
    }

    fn path_to(&self, destination: IsdAsn, now: Instant) -> Result<Option<&Path>, PathFetchError> {
        self.get_strategy(destination)?.path_to(destination, now)
    }

    fn is_path_available(&self, destination: IsdAsn, now: Instant) -> Result<bool, PathFetchError> {
        self.get_strategy(destination)?
            .is_path_available(destination, now)
    }

    fn poll_requests(&mut self, now: Instant) -> Request {
        self.fill_missing_destinations();

        let mut earliest_callback = Duration::MAX;
        for strategy in self.inner.values_mut() {
            match strategy.poll_requests(now) {
                lookup @ Request::LookupPathsTo(_) => return lookup,
                Request::Callback(callback) => {
                    earliest_callback = cmp::min(callback, earliest_callback)
                }
            }
        }

        Request::Callback(earliest_callback)
    }

    /// Caches the provided paths.
    ///
    /// When providing paths for different destinations, several calls to `handle_lookup_paths` should be
    /// made, as this function considers the destination of the first path to be representative of all
    /// destinations.
    fn handle_lookup_paths(&mut self, paths: &[Path], now: Instant) {
        let Some(sample_path) = paths.first() else {
            return;
        };
        if sample_path.destination().is_wildcard() {
            return;
        }

        self.fill_missing_destinations();
        self.get_or_insert(sample_path.destination())
            .handle_lookup_paths(paths, now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pan::path_strategy::{
        refresher::PathRefresher,
        test_utils::{assert_paths_unordered_eq, get_unexpired_paths, param_test},
    };

    const REMOTE_IA: IsdAsn = IsdAsn(0x1_ff00_0000_0001);
    const OTHER_IA: IsdAsn = IsdAsn(0x2_ff00_0000_0002);

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
    type GetPathsFn =
        fn(&UniformStrategy<PathRefresher>, IsdAsn, Instant) -> Result<Vec<Path>, PathFetchError>;

    fn get_strategy() -> UniformStrategy<PathRefresher> {
        UniformStrategy::new(PathRefresher::new)
    }

    fn get_multiple_paths_to(
        strategy: &UniformStrategy<PathRefresher>,
        destination: IsdAsn,
        now: Instant,
    ) -> Result<Vec<Path>, PathFetchError> {
        strategy
            .paths_to(destination, now)
            .map(|iter| iter.cloned().collect())
    }

    fn get_single_path_to(
        strategy: &UniformStrategy<PathRefresher>,
        destination: IsdAsn,
        now: Instant,
    ) -> Result<Vec<Path>, PathFetchError> {
        strategy
            .path_to(destination, now)
            .map(|maybe_path| maybe_path.into_iter().cloned().collect())
    }

    fn performs_lookups_to_previously_requested_destinations(get_path: GetPathsFn) {
        let mut strategy = get_strategy();

        assert_eq!(
            get_path(&strategy, REMOTE_IA, Instant::now()),
            Err(PathFetchError::RequiresPoll)
        );
        assert_eq!(
            strategy.poll_requests(Instant::now()),
            Request::LookupPathsTo(REMOTE_IA)
        );
    }

    param_test! {
        performs_lookups_to_previously_requested_destinations: [
            single_path: get_single_path_to,
            multiple_paths: get_multiple_paths_to
        ]
    }

    fn stores_and_returns_paths(n_paths: usize, get_paths: GetPathsFn) -> TestResult {
        let mut strategy = get_strategy();

        let remote_paths = get_unexpired_paths(REMOTE_IA, n_paths);
        strategy.handle_lookup_paths(&remote_paths, Instant::now());

        let other_paths = get_unexpired_paths(OTHER_IA, n_paths);
        strategy.handle_lookup_paths(&other_paths, Instant::now());

        let returned_remote_paths = get_paths(&strategy, REMOTE_IA, Instant::now())?;
        assert_paths_unordered_eq!(returned_remote_paths, remote_paths);

        let returned_other_paths = get_paths(&strategy, OTHER_IA, Instant::now())?;
        assert_paths_unordered_eq!(returned_other_paths, other_paths);

        Ok(())
    }

    param_test! {
        stores_and_returns_paths -> TestResult: [
            single_path: (1, get_single_path_to),
            multiple_paths: (3, get_multiple_paths_to)
        ]
    }

    fn get_paths_errs_on_wildcard(remote_ia: &str, get_path: GetPathsFn) {
        let strategy = get_strategy();
        let remote_ia: IsdAsn = remote_ia.parse().unwrap();
        let result = get_path(&strategy, remote_ia, Instant::now());

        assert_eq!(result, Err(PathFetchError::UnsupportedDestination));
    }

    param_test! {
        get_paths_errs_on_wildcard -> (): [
            single_path_wildcard_asn: ("1-0", get_single_path_to),
            single_path_wildcard_isd: ("0-ff00:0:110", get_single_path_to),
            single_path_wildcard_ia: ("0-0", get_single_path_to),
            multiple_paths_wildcard_asn: ("1-0", get_multiple_paths_to),
            multiple_paths_wildcard_isd: ("0-ff00:0:110", get_multiple_paths_to),
            multiple_paths_wildcard_ia: ("0-0", get_multiple_paths_to)
        ]
    }
}
