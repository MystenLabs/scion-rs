use std::{
    collections::HashSet,
    future::Future,
    sync::{Arc, Mutex},
};

use futures::stream::{FuturesUnordered, StreamExt};
use scion_proto::{address::IsdAsn, path::Path};
use tokio::{sync::watch, task::JoinHandle, time, time::Instant};

use super::PathStrategy;
use crate::pan::{
    path_service::PathLookupError,
    path_strategy::{PathFetchError, Request},
    AsyncPathService,
};

/// An asynchronous wrapper around a [`PathStrategy`].
///
/// Creating a new `AsyncPathStrategy` starts a background task that uses the provided
/// [`PathStrategy`] to determine when to query paths on the provided [`AsyncPathService`]
/// and when to probe the found paths on the network.
///
/// Aspects such as timeout and retries should be handled by the [`AsyncPathService`].
///
/// Shortly after creation, the [`poll_requests`][PathStrategy::poll_requests] is called
/// on the underlying path strategy. The timings of subsequent calls to `poll_requests` are
/// dictated by the [`Request`]s returned from their prior invocations.
///
/// The actions taken by the `AsyncPathStrategy` are informed by the values of the returned
/// [`Request`]:
///
/// - [`Request::LookupPathsTo`] - Queries the configured [`AsyncPathService`] for paths
///   to the specified destination. This is only performed if there are no outstanding
///   lookups for that destination. In the event that there is a pending lookup, the request
///   is discarded.
///
/// - [`Request::Callback`] - Calls [`poll_requests`][PathStrategy::poll_requests] after the
///   specified duration has elapsed. Only the most recent callback request is observed, and
///   the strategy may be called sooner if paths arrive before the duration has elapsed.
///
/// Dropping the `AsyncPathStrategy` aborts the background task.
#[derive(Debug)]
pub struct AsyncPathStrategy<S, P> {
    inner: Arc<AsyncPathStrategyInner<S, P>>,
    background_task: JoinHandle<()>,
}

impl<S, P> AsyncPathStrategy<S, P>
where
    S: PathStrategy + Send + 'static,
    P: AsyncPathService + Send + Sync + 'static,
{
    /// Creates a new `AsyncPathStrategy` and spawns a background task to drive the strategy.
    ///
    /// The provided [`PathStrategy`] determines the logic and the provided [`AsyncPathService`]
    /// is used to fulfil path requests from the strategy.
    ///
    /// This must be called within a tokio async context (such as within an async function).
    pub fn new(strategy: S, path_service: P) -> Self {
        let inner = Arc::new(AsyncPathStrategyInner::new(strategy, path_service));
        Self {
            background_task: tokio::spawn(inner.clone().drive_strategy()),
            inner,
        }
    }

    #[tracing::instrument(skip(self, handler))]
    async fn on_paths_available<F, T>(
        &self,
        scion_as: IsdAsn,
        handler: F,
    ) -> Result<T, PathLookupError>
    where
        F: FnOnce(&S, Instant) -> Result<T, PathLookupError>,
    {
        let start = Instant::now();
        let mut update_listener = self.inner.subscribe_to_path_changes();

        loop {
            {
                let now = Instant::now();
                let rel_now = now.duration_since(start);
                let strategy = self.inner.strategy.lock().unwrap();

                match strategy.is_path_available(scion_as, now.into()) {
                    Err(PathFetchError::UnsupportedDestination) => {
                        tracing::debug!("request was for unsupported destination");
                        return Err(PathLookupError::UnsupportedDestination);
                    }
                    Ok(true) => {
                        tracing::debug!(now=?rel_now, "paths are available, running handler");
                        return handler(&*strategy, now);
                    }
                    Ok(false) => tracing::debug!(now = ?rel_now, "no paths currently available"),
                }
            }

            tracing::debug!("waiting until the path strategy has received paths");
            if update_listener.changed().await.is_err() {
                tracing::warn!("channel dropped while waiting, aborting wait");
                return Err(PathLookupError::NoPath);
            }
        }
    }
}

impl<S, P> AsyncPathService for AsyncPathStrategy<S, P>
where
    S: PathStrategy + Send + 'static,
    P: AsyncPathService + Send + Sync + 'static,
{
    type PathsTo = std::vec::IntoIter<Path>;

    async fn paths_to(&self, scion_as: IsdAsn) -> Result<Self::PathsTo, PathLookupError> {
        self.on_paths_available(scion_as, |strategy, now| {
            let available_paths: Vec<Path> = strategy
                .paths_to(scion_as, now.into())
                .expect("available paths as reported by is_path_available")
                .cloned()
                .collect();
            Ok(available_paths.into_iter())
        })
        .await
    }

    async fn path_to(&self, scion_as: IsdAsn) -> Result<Path, PathLookupError> {
        self.on_paths_available(scion_as, |strategy, now| {
            let path: Path = strategy
                .path_to(scion_as, now.into())
                .expect("valid choice of destination")
                .expect("at least 1 path available")
                .clone();
            Ok(path)
        })
        .await
    }
}

impl<S, P> AsyncPathStrategy<S, P> {
    fn abort_background_task(&self) {
        self.background_task.abort()
    }
}

impl<S, P> Drop for AsyncPathStrategy<S, P> {
    fn drop(&mut self) {
        self.abort_background_task();
    }
}

#[derive(Debug)]
struct AsyncPathStrategyInner<S, P> {
    path_service: P,
    strategy: Mutex<S>,
    update_notifier: watch::Sender<()>,
}

impl<'p, S, P> AsyncPathStrategyInner<S, P>
where
    S: PathStrategy + Send,
    P: AsyncPathService + Send + Sync,
{
    fn new(strategy: S, path_service: P) -> Self {
        Self {
            strategy: Mutex::new(strategy),
            path_service,
            update_notifier: watch::Sender::new(()),
        }
    }

    #[tracing::instrument(skip(self))]
    async fn drive_strategy(self: Arc<AsyncPathStrategyInner<S, P>>) {
        let mut requests = PendingRequests::new();
        let mut found_paths = vec![];

        let start = Instant::now();
        loop {
            let callback_time: Instant = {
                let now = Instant::now();
                let _span =
                    tracing::debug_span!("request_check", now=?now.duration_since(start)).entered();

                let mut strategy = self.strategy.lock().unwrap();

                // Repeatedly polls requests from the underlying strategy.
                //
                // Note that since the only way to exit the loop below is on a callback, the
                // strategy must eventually return a Callback when called repeatedly with the
                // same 'now' instant.
                tracing::debug!("checking for path strategy requests");
                loop {
                    match strategy.poll_requests(now.into()) {
                        Request::LookupPathsTo(scion_as) => {
                            let path_service = &self.path_service;
                            requests.lookup_if_not_pending(scion_as, |ia| async move {
                                (ia, path_service.paths_to(ia).await)
                            });
                        }
                        Request::Callback(delay) => {
                            tracing::debug!(?delay, "callback requested");
                            break now + delay;
                        }
                    }
                }
            };

            tracing::debug!(
                callback_time=?callback_time.duration_since(start), "waiting for paths or callback timeout"
            );

            // Wait for the callback duration, or until a pending path query completes. If there
            // are no pending path queries, then this will just sleep until the callback time.
            while let Ok(next) = time::timeout_at(callback_time, requests.next_ready()).await {
                let span = tracing::debug_span!("event_wait", now=?start.elapsed());

                match next {
                    Some((scion_as, Err(err))) => {
                        span.in_scope(
                            || tracing::warn!(%scion_as, %err, "ignoring path lookup failure"),
                        );
                        continue;
                    }
                    Some((scion_as, Ok(paths))) => {
                        let _guard = span.enter();
                        let mut strategy = self.strategy.lock().unwrap();

                        found_paths.clear();
                        found_paths.extend(paths);

                        tracing::debug!(%scion_as, count=found_paths.len(), "path lookup successful");
                        strategy.handle_lookup_paths(&found_paths, Instant::now().into());

                        self.update_notifier.send_replace(());

                        break;
                    }
                    None => {
                        span.in_scope(|| tracing::debug!("no pending path lookups remaining"));
                        time::sleep_until(callback_time).await;
                        break;
                    }
                }
            }
        }
    }

    fn subscribe_to_path_changes(&self) -> watch::Receiver<()> {
        self.update_notifier.subscribe()
    }
}

/// Tracks the ASes for which path requests are pending.
#[derive(Debug)]
struct PendingRequests<F> {
    lookup_destinations: HashSet<IsdAsn>,
    futures: FuturesUnordered<F>,
}

impl<F, I> PendingRequests<F>
where
    F: Future<Output = (IsdAsn, Result<I, PathLookupError>)>,
    I: Iterator<Item = Path>,
{
    fn new() -> Self {
        Self {
            lookup_destinations: Default::default(),
            futures: Default::default(),
        }
    }

    /// Creates a future to lookup a path to the specified SCION AS, using the
    /// provided lookup function, if there is no future already pending for that AS.
    ///
    /// Returns true if a new future was created, otherwise false.
    fn lookup_if_not_pending<G>(&mut self, scion_as: IsdAsn, lookup_fn: G) -> bool
    where
        G: FnOnce(IsdAsn) -> F,
    {
        if self.lookup_destinations.insert(scion_as) {
            tracing::debug!(%scion_as, "scheduling task for path lookup");
            self.futures.push((lookup_fn)(scion_as));
            true
        } else {
            tracing::debug!(%scion_as, "lookup already pending, discarding repeated request");
            false
        }
    }

    fn is_empty(&self) -> bool {
        self.lookup_destinations.is_empty()
    }

    async fn next_ready(&mut self) -> Option<F::Output> {
        // If StreamExt::next is allowed to return None, then it's invalid
        // to call it again; therefore, only call it if the set is not empty.
        if self.is_empty() {
            return None;
        }

        if let Some((scion_as, result)) = self.futures.next().await {
            let was_present = self.lookup_destinations.remove(&scion_as);
            debug_assert!(was_present);

            Some((scion_as, result))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error, time::Duration};

    use scion_proto::{address::IsdAsn, packet::ByEndpoint};

    use super::*;
    use crate::pan::{path_strategy::PathStrategy, AsyncPathService};

    /// An arbitrary, non-wildcard IsdAsn.
    const REMOTE_IA: IsdAsn = IsdAsn(0x1_ff00_0000_0001);

    macro_rules! async_param_test {
        ($func_name:ident: [
            $( $case_name:ident: ($($arg:expr),*) ),*
        ]) => {
            mod $func_name {
                use super::*;

                $(
                    #[tokio::test(start_paused = true)]
                    async fn $case_name() {
                        $func_name($($arg, )*).await
                    }
                )*
            }
        };
        ($func_name:ident: [
            $( $case_name:ident: $arg:expr ),*
        ]) => {
            async_param_test!($func_name: [ $($case_name: ($arg)),* ]);
        };
    }

    /// Module with mock helpers.
    ///
    /// Separated from the tests as they use a different type of Instant.
    mod mocks {

        use std::{
            future::{self},
            time::{Duration, Instant},
        };

        use futures::future::BoxFuture;
        use mockall::mock;
        use scion_proto::{address::IsdAsn, packet::ByEndpoint, path::Path};

        use super::*;
        use crate::pan::{
            path_service::PathLookupError,
            path_strategy::{PathFetchError, PathStrategy, Request},
            AsyncPathService,
        };

        #[inline]
        pub fn millisecs(milliseconds: u64) -> Duration {
            Duration::from_millis(milliseconds)
        }

        mock! {
            pub Strategy { }

            impl PathStrategy for Strategy {
                type PathsTo<'p> = std::vec::IntoIter<&'p Path>;

                fn paths_to<'a>(
                    &'a self, destination: IsdAsn, now: Instant
                ) -> Result<<Self as PathStrategy>::PathsTo<'a>, PathFetchError>;

                fn path_to<'a>(
                    &'a self,
                    destination: IsdAsn,
                    now: Instant,
                ) -> Result<Option<&'a Path>, PathFetchError>;
                fn poll_requests(&mut self, now: Instant) -> Request;
                fn handle_lookup_paths(&mut self, paths: &[Path], now: Instant);
                fn is_path_available(&self, destination: IsdAsn, now: Instant) -> Result<bool, PathFetchError>;
            }
        }

        impl MockStrategy {
            /// Returns a `MockStrategy` with a default implementation of `handle_lookup_paths`
            /// that accepts all provided paths.
            pub fn that_accepts_any_path() -> Self {
                let mut strategy = MockStrategy::new();
                strategy.expect_handle_lookup_paths().return_const(());
                strategy
            }

            /// Returns a `MockStrategy` that requests a path to REMOTE_IA initially then only
            /// returns callback requests.
            pub fn single_lookup() -> Self {
                let mut strategy = MockStrategy::new();
                strategy
                    .expect_poll_requests()
                    .returning(identical_lookups_then_callback(1, millisecs(1000)));
                strategy
            }
        }

        /// Creates a mock of `poll_requests` that returns a lookup request to [`REMOTE_IA`]
        /// followed by 10 ms callbacks.
        pub fn arbitrary_lookup() -> impl FnMut(Instant) -> Request {
            identical_lookups_then_callback(1, millisecs(10))
        }

        /// Creates a mock of `poll_requests` that returns the specified number of lookup requests
        /// to [`REMOTE_IA`] followed by callbacks of the specified duration.
        pub fn identical_lookups_then_callback(
            n_lookups: usize,
            duration: Duration,
        ) -> impl FnMut(Instant) -> Request {
            lookups_then_callback(n_lookups, duration, false)
        }

        /// Creates a mock of `poll_requests` that returns several unique lookup requests
        /// followed by callbacks of the specified duration.
        ///
        /// The first lookup request is for [`REMOTE_IA`], with each subsequent one requesting
        /// the next sequential IsdAsn.
        pub fn unique_lookups_then_callback(
            n_lookups: usize,
            duration: Duration,
        ) -> impl FnMut(Instant) -> Request {
            lookups_then_callback(n_lookups, duration, true)
        }

        pub fn lookups_then_callback(
            mut n_lookups: usize,
            duration: Duration,
            unique_lookups: bool,
        ) -> impl FnMut(Instant) -> Request {
            let original_n_lookups = n_lookups;

            move |_: Instant| {
                if n_lookups == 0 {
                    return Request::Callback(duration);
                }
                n_lookups -= 1;

                let offset: u64 = if unique_lookups {
                    (original_n_lookups - n_lookups - 1) as u64
                } else {
                    0
                };
                Request::LookupPathsTo(IsdAsn(REMOTE_IA.0 + offset))
            }
        }

        /// Creates a mock of `poll_requests` that requests path lookups to REMOTE_IA, after
        /// the configured period has elapsed since the last request was sent.
        pub fn periodic_lookups(period: Duration) -> impl FnMut(Instant) -> Request {
            let mut last_lookup: Option<Instant> = None;
            move |now| {
                if let Some(time) = last_lookup {
                    let time_until_lookup = (time + period).duration_since(now);
                    if time_until_lookup != Duration::ZERO {
                        return Request::Callback(time_until_lookup);
                    }
                }

                last_lookup = Some(now);
                Request::LookupPathsTo(REMOTE_IA)
            }
        }

        /// Mock of `poll_requests` that repeatedly requests callbacks of 10 ms.
        pub fn repeated_callbacks(_: Instant) -> Request {
            Request::Callback(millisecs(10))
        }

        /// Creates a mock of `poll_requests` that repeatedly requests callbacks of the
        /// provided duration.
        pub fn repeated_callbacks_with_duration(
            period: Duration,
        ) -> impl FnMut(Instant) -> Request {
            move |_| Request::Callback(period)
        }

        mock! {
            pub PathService { }

            impl AsyncPathService for PathService {
                type PathsTo = std::vec::IntoIter<Path>;

                fn paths_to(
                    &self, scion_as: IsdAsn
                ) -> impl Future<
                    Output = Result<<MockPathService as AsyncPathService>::PathsTo, PathLookupError>
                > + Send;

                fn path_to(
                    &self, scion_as: IsdAsn
                ) ->  impl Future<Output = Result<Path, PathLookupError>> + Send;
            }
        }

        impl MockPathService {
            /// Gets a path service that returns arbitrary paths an unbounded number of times.
            pub fn returning_arbitrary_paths() -> Self {
                let mut path_service = MockPathService::new();
                path_service.expect_paths_to().returning(arbitrary_paths);
                path_service
            }

            /// Returns a path service that never completes.
            pub fn that_never_completes() -> Self {
                let mut path_service = MockPathService::new();
                path_service.expect_paths_to().returning(never_completes);
                path_service
            }

            /// Returns a path service that returns arbitrary paths after a delay.
            pub fn returning_paths_after_a_delay(delay: Duration) -> Self {
                let mut path_service = MockPathService::new();
                path_service
                    .expect_paths_to()
                    .returning(paths_after_a_delay(delay));
                path_service
            }
        }

        type BoxedPathsToFuture = BoxFuture<
            'static,
            Result<<MockPathService as AsyncPathService>::PathsTo, PathLookupError>,
        >;

        /// Creates a mock of [`AsyncPathService::paths_to`] that returns a vector of a single,
        /// empty path for the specified scion AS.
        pub fn arbitrary_paths(scion_as: IsdAsn) -> BoxedPathsToFuture {
            let path = Path::empty(ByEndpoint::with_cloned(scion_as));
            Box::pin(future::ready(Ok(vec![path].into_iter())))
        }

        /// Creates a mock of [`AsyncPathService::paths_to`] that never completes.
        pub fn never_completes(_: IsdAsn) -> BoxedPathsToFuture {
            Box::pin(async {
                loop {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                }
            })
        }

        /// Creates a mock of `paths_to` that returns an arbitrary path after a delay.
        pub fn paths_after_a_delay(delay: Duration) -> impl FnMut(IsdAsn) -> BoxedPathsToFuture {
            move |scion_as| {
                Box::pin(async move {
                    tokio::time::sleep(delay).await;

                    let path = Path::empty(ByEndpoint::with_cloned(scion_as));
                    Ok(vec![path].into_iter())
                })
            }
        }

        pub fn any_path_to(scion_as: IsdAsn) -> impl Fn(&[Path], &Instant) -> bool {
            move |paths: &[Path], _: &Instant| {
                paths
                    .iter()
                    .map(|p| p.isd_asn.destination)
                    .any(|ia| ia == scion_as)
            }
        }
    }

    use mocks::*;

    async fn run_path_strategy<S, P>(strategy: S, path_service: P, run_duration: Duration)
    where
        S: PathStrategy + Send + 'static,
        P: AsyncPathService + Send + Sync + 'static,
    {
        let mut async_strategy = AsyncPathStrategy::new(strategy, path_service);

        // Get the background task so that we can join on it
        let mut background_task = tokio::spawn(async {});
        std::mem::swap(&mut background_task, &mut async_strategy.background_task);

        let start_time = tokio::time::Instant::now();
        let delayed_abort_task = tokio::spawn(async move {
            // We use sleep_until here because it's unclear what the current instant
            // will be when this is actually executed.
            tokio::time::sleep_until(start_time + run_duration).await;

            // We do not need to use join or anything as this assumes simulated time.
            background_task.abort();
            let _ = background_task.await;
        });

        // Increment the time in 0.1 ms intervals up to the run duration
        let increment = Duration::from_micros(100);
        let end_time = Instant::now() + run_duration;
        while Instant::now() < end_time {
            tokio::time::advance(increment).await
        }

        let _ = delayed_abort_task.await;
    }

    #[tokio::test(start_paused = true)]
    async fn forwards_path_requests() {
        let mut strategy = MockStrategy::new();
        let mut path_service = MockPathService::new();

        strategy
            .expect_poll_requests()
            .returning(arbitrary_lookup())
            .times(1..);

        path_service
            .expect_paths_to()
            .returning(never_completes)
            .times(1..);

        run_path_strategy(strategy, path_service, millisecs(10)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn makes_no_path_requests_unless_requested() {
        let mut strategy = MockStrategy::new();
        let mut path_service = MockPathService::new();

        strategy
            .expect_poll_requests()
            .returning(repeated_callbacks);

        path_service.expect_paths_to().never();

        run_path_strategy(strategy, path_service, millisecs(10)).await;
    }

    async fn polls_until_callback(n_lookups: usize) {
        let mut strategy = MockStrategy::new();
        let path_service = MockPathService::returning_arbitrary_paths();

        strategy
            .expect_poll_requests()
            .returning(identical_lookups_then_callback(n_lookups, millisecs(100)))
            .times(n_lookups + 1);

        run_path_strategy(strategy, path_service, millisecs(10)).await;
    }

    async_param_test! {
        polls_until_callback: [
            one_lookup: 1,
            two_lookups: 2,
            ten_lookups: 10
        ]
    }

    #[tokio::test(start_paused = true)]
    async fn ignores_same_ia_requests_when_pending() {
        let mut strategy = MockStrategy::new();
        let mut path_service = MockPathService::new();

        strategy
            .expect_poll_requests()
            .returning(identical_lookups_then_callback(2, millisecs(10)))
            .times(2..);

        path_service
            .expect_paths_to()
            .returning(never_completes)
            .times(1);

        run_path_strategy(strategy, path_service, millisecs(10)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn performs_parallel_unique_lookups() {
        let mut strategy = MockStrategy::new();
        let mut path_service = MockPathService::new();

        strategy
            .expect_poll_requests()
            .returning(unique_lookups_then_callback(2, millisecs(10)))
            .times(2..);

        path_service
            .expect_paths_to()
            .returning(never_completes)
            .times(2);

        run_path_strategy(strategy, path_service, millisecs(10)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn performs_non_overlapping_repeated_lookups() {
        let mut strategy = MockStrategy::new();
        let path_service = MockPathService::returning_arbitrary_paths();

        let run_duration_ms = 44u64;
        let lookup_period_ms = 15u64;
        // These correspond to the lookups at 0 ns, 15 ns, 30 ns
        let expected_successful_lookups = run_duration_ms / lookup_period_ms + 1;

        strategy
            .expect_poll_requests()
            .returning(periodic_lookups(millisecs(lookup_period_ms)));

        strategy
            .expect_handle_lookup_paths()
            .return_const(())
            .times(expected_successful_lookups as usize);

        run_path_strategy(strategy, path_service, millisecs(run_duration_ms)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn provides_looked_up_paths_to_strategy() {
        let mut strategy = MockStrategy::new();
        let path_service = MockPathService::returning_arbitrary_paths();

        strategy
            .expect_poll_requests()
            .returning(unique_lookups_then_callback(2, millisecs(10)));
        strategy
            .expect_handle_lookup_paths()
            .return_const(())
            .withf(any_path_to(REMOTE_IA))
            .times(1);
        strategy
            .expect_handle_lookup_paths()
            .return_const(())
            .withf(any_path_to(IsdAsn(REMOTE_IA.as_u64() + 1)))
            .times(1);

        run_path_strategy(strategy, path_service, millisecs(10)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn calls_back_after_providing_paths() {
        let mut strategy = MockStrategy::new();
        let path_service = MockPathService::returning_arbitrary_paths();

        strategy
            .expect_poll_requests()
            .returning(unique_lookups_then_callback(1, millisecs(1000)))
            // Should be called thrice: once for the lookup, once to receive the callback
            // request, and once because it delivered paths.
            .times(3..);

        strategy.expect_handle_lookup_paths().return_const(());

        run_path_strategy(strategy, path_service, millisecs(10)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn calls_back_when_requested() {
        let mut strategy = MockStrategy::that_accepts_any_path();
        let path_service = MockPathService::returning_arbitrary_paths();

        let start = Instant::now();

        strategy
            .expect_poll_requests()
            .returning(repeated_callbacks_with_duration(millisecs(30)))
            .times(1);
        strategy
            .expect_poll_requests()
            .returning(repeated_callbacks_with_duration(millisecs(30)))
            .withf(move |now| {
                let now = Instant::from_std(*now);
                now > (start + millisecs(30)) && now <= (start + millisecs(35))
            })
            .times(1);

        run_path_strategy(strategy, path_service, millisecs(35)).await;
    }

    #[tokio::test]
    async fn returns_available_paths() -> Result<(), Box<dyn Error>> {
        let mut strategy = MockStrategy::that_accepts_any_path();
        let path_service = MockPathService::that_never_completes();

        strategy.expect_path_to().returning(|ia, _| {
            let path: Box<_> = Path::empty(ByEndpoint::with_cloned(ia)).into();
            Ok(Some(Box::leak(path)))
        });
        strategy
            .expect_is_path_available()
            .returning(|_, _| Ok(true));

        let async_strategy = AsyncPathStrategy::new(strategy, path_service);
        let path = tokio::time::timeout(millisecs(5), async_strategy.path_to(REMOTE_IA)).await??;

        assert_eq!(path.isd_asn.destination, REMOTE_IA);

        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn waits_for_available_paths() -> Result<(), Box<dyn Error>> {
        let path_service = MockPathService::returning_paths_after_a_delay(millisecs(20));
        let mut strategy = MockStrategy::single_lookup();

        let path_store: Arc<Mutex<Option<Path>>> = Arc::new(Mutex::new(None));

        let path_to_path = path_store.clone();
        strategy.expect_path_to().returning(move |ia, _| {
            let maybe_path = path_to_path.lock().unwrap();

            if let Some(path) = maybe_path.as_ref() {
                if path.isd_asn.destination == ia {
                    let path = Box::new(path.clone());
                    return Ok(Some(Box::leak(path)));
                }
            }

            Ok(None)
        });

        let is_path_available_path = path_store.clone();
        strategy.expect_is_path_available().returning(move |ia, _| {
            let maybe_path = is_path_available_path.lock().unwrap();

            if let Some(path) = maybe_path.as_ref() {
                Ok(path.isd_asn.destination == ia)
            } else {
                Ok(false)
            }
        });

        let handle_lookup_paths_path = path_store.clone();
        strategy
            .expect_handle_lookup_paths()
            .returning(move |paths, _| {
                let _ = handle_lookup_paths_path
                    .lock()
                    .unwrap()
                    .insert(paths[0].clone());
            });

        let async_strategy = AsyncPathStrategy::new(strategy, path_service);
        let path = tokio::time::timeout(millisecs(30), async_strategy.path_to(REMOTE_IA)).await??;

        assert_eq!(path.isd_asn.destination, REMOTE_IA);

        Ok(())
    }
}
