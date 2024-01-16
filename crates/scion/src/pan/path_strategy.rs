//! Strategies for caching and selecting paths.
use std::time::{Duration, Instant};

use scion_proto::{address::IsdAsn, path::Path};

mod async_strategy;
pub use async_strategy::AsyncPathStrategy;

/// Errors returned when fetching paths from a [`PathStrategy`].
#[derive(Debug, thiserror::Error)]
pub enum PathFetchError {
    /// The requested destination is not supported by this strategy,
    /// and will never return a valid result.
    #[error("the requested destination is not supported by this strategy")]
    UnsupportedDestination,
}

/// Requests that a path strategy can make on its controller.
pub enum Request {
    /// Requests that the controller queries paths to the specified destination.
    LookupPathsTo(IsdAsn),
    /// Requests that the controller calls back the strategy after the specified duration.
    Callback(Duration),
}

/// Trait for objects defining the strategy for querying and caching paths.
///
/// An implementation of a `PathStrategy` serves three functions, it
///
/// - defines a state machine that determines when and for which ASes path queries
///   should be made;
/// - filters and caches the returned paths; and
/// - determines, which paths to provide to clients based on specific and possibly
///   configurable metrics.
///
/// The resulting state machine may be expected to be used as follows. After initialization,
/// an initial call to [`poll_request`][Self::poll_requests] is made to determine the initial
/// request. While `poll_requests` returns a request for a path query ([`Request::LookupPathsTo`]),
/// it must be called repeatedly until it returns a request for a callback at a later time
/// ([`Request::Callback`]).
///
/// While waiting for its callback, one or more paths may arrive and be processed with
/// [`handle_lookup_paths`][Self::handle_lookup_paths]; after which, a call to `poll_requests`
/// must be immediately made as handling the incoming paths may cause new requests to be
/// generated. If no paths arrive before the callback duration, `poll_requests` is directly
/// called.
///
/// This flow is depicted in the following diagram:
///
/// ```text
///                LookupPathsTo(_)
///                ┌───┐
///  ┌──────┐   ┌──▼───┴────────────┐Callback(_)  ┌─────────┐
///  │*Init*├──►│ poll_requests(..) ├────────────►│*Waiting*│
///  └──────┘   └─────────▲──────▲──┘    *timeout*└─┬───┬───┘
///                       │      └──────────────────┘   │
///                       │                             │
///               ┌─────┐ │           *lookup completes*│
///   *more paths*│   ┌─▼─┴─────────────────────┐       │
///               └───┤ handle_lookup_paths(..) │◄──────┘
///                   └─────────────────────────┘
/// ```
///
/// See also [`AsyncPathStrategy`] which wraps the a provided `PathStrategy` and asynchronously
/// handles its requests for callbacks and path queries.
pub trait PathStrategy {
    /// Iterator over paths cached by the strategy.
    type PathsTo<'p>: Iterator<Item = &'p Path>
    where
        Self: 'p;

    /// Returns an iterator over paths cached by the path strategy.
    ///
    /// The order of the paths is implementation dependent.
    fn paths_to(
        &self,
        destination: IsdAsn,
        now: Instant,
    ) -> Result<Self::PathsTo<'_>, PathFetchError>;

    /// Returns a path from the local cache, as chosen by the strategy.
    fn path_to(&self, destination: IsdAsn, now: Instant) -> Result<Option<&Path>, PathFetchError>;

    /// Returns true if there are paths available to the destination at the provided point in time.
    ///
    /// Subsequent call to [`path_to`][Self::path_to] or [`paths_to`][Self::paths_to] for the given
    /// value of `now` are guaranteed to return at least one path.
    ///
    /// Errs if the destination ISD AS is not supported by this service.
    fn is_path_available(&self, destination: IsdAsn, now: Instant) -> Result<bool, PathFetchError>;

    /// Polls the `PathStrategy` for new [`Request`]s.
    ///
    /// For a given `now` instant, repeated calls to this method should return requests that it
    /// expects to be handled before the next callback, followed by a [`Request::Callback`] which
    /// indicates the end of the stream of requests for the given `now` instant.
    ///
    /// In addition to after the specified callback, this method must be called after the creation
    /// of the strategy and after [`handle_lookup_paths`][Self::handle_lookup_paths] is called.
    fn poll_requests(&mut self, now: Instant) -> Request;

    /// Filter and store the provided paths.
    ///
    /// The provided paths should correspond to an earlier request, but implementations
    /// should be prepared to filter and discard paths to an unexpected destination.
    fn handle_lookup_paths(&mut self, paths: &[Path], now: Instant);
}
