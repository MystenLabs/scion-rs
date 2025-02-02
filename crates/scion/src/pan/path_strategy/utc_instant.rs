use std::time::Instant;

use chrono::{DateTime, Duration as ChronoDuration, Utc};

/// Utility to map between [`Instant`] and [`DateTime<Utc>`].
///
/// All conversions occur relative to a reference start time, which is set when and
/// instant is created with [`UtcReferenceInstant::now()`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct UtcInstant {
    time: DateTime<Utc>,
    instant: Instant,
}

impl UtcInstant {
    /// Creates a new reference instant corresponding to now.
    pub fn now() -> Self {
        Self {
            time: Utc::now(),
            instant: Instant::now(),
        }
    }

    /// Returns the [`DateTime<Utc>`] associated with this `UtcInstant`.
    #[cfg(test)]
    pub const fn time(&self) -> DateTime<Utc> {
        self.time
    }

    /// Returns the [`Instant`] associated with this `UtcInstant`.
    #[cfg(test)]
    pub const fn instant(&self) -> Instant {
        self.instant
    }

    /// Converts the provided [`Instant`] to a [`DateTime<Utc>`] relative to this `UtcInstant`.
    ///
    /// The result returned by this method saturates at `self.time()` and [`DateTime::<Utc>::MAX_UTC`].
    /// Therefore, passing an instant less than `self.instant()` will return `self.time()`.
    pub fn instant_to_utc(&self, instant: Instant) -> DateTime<Utc> {
        let duration_since_reference = instant.duration_since(self.instant);

        // Convert to a chrono::Duration. This conversion would fail if the the StdDuration is larger than
        // the max chrono::Duration, but in that case, the value would anyway result in MAX_UTC.
        ChronoDuration::from_std(duration_since_reference)
            .ok()
            .and_then(|duration| self.time.checked_add_signed(duration))
            .unwrap_or(DateTime::<Utc>::MAX_UTC)
    }
}

impl From<UtcInstant> for DateTime<Utc> {
    fn from(value: UtcInstant) -> Self {
        value.time
    }
}

impl From<UtcInstant> for Instant {
    fn from(value: UtcInstant) -> Self {
        value.instant
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn addition_with_max_chrono_duration_saturates_datetime() {
        let datetime = DateTime::<Utc>::MIN_UTC;
        assert_eq!(datetime.checked_add_signed(ChronoDuration::MAX), None);
    }
}
