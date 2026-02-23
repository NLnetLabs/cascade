//! Scheduling events.
//!
//! Cascade takes a very particular approach to event scheduling. While it could
//! just use Tokio timers, transparency is very important, and it's important to
//! be able to look up currently scheduled events. This module implements a very
//! simple concurrent event scheduler for this purpose.

use std::{
    borrow::{Borrow, BorrowMut},
    collections::BTreeSet,
    convert::Infallible,
    fmt::Debug,
    sync::Mutex,
    time::{Duration, Instant},
};

use tokio::sync::watch;
use tracing::trace;

//----------- Scheduler --------------------------------------------------------

/// A transparent event scheduler.
#[derive(Debug)]
pub struct Scheduler<T> {
    /// The current schedule.
    schedule: Mutex<BTreeSet<ScheduledItem<T>>>,

    /// The earliest scheduled time.
    ///
    /// This is wrapped in a [`tokio::sync::watch`]er, so that the scheduler's
    /// runner can watch for changes asynchronously.
    ///
    /// This should only be updated while [`Self::schedule`] is locked, ensuring
    /// consistency between the two.
    earliest: watch::Sender<Option<Instant>>,
}

impl<T> Scheduler<T> {
    /// Construct a new [`Scheduler`].
    pub fn new() -> Self {
        Self {
            schedule: Mutex::new(BTreeSet::new()),
            earliest: watch::Sender::new(None),
        }
    }
}

impl<T> Default for Scheduler<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Ord + Clone + Debug> Scheduler<T> {
    /// Update the scheduling of an item.
    ///
    /// This method can be used to schedule an item, update its schedule, or
    /// remove it from the schedule, depending on the parameters `old` and
    /// `new`.
    ///
    /// `old` is the current state of the item in the schedule. If it is
    /// `Some(time)`, the item was previously scheduled at `time`; if it is
    /// `None`, the item was not in the schedule.
    ///
    /// `new` in the target state of the item in the schedule. If it is
    /// `Some(time)`, the item will be scheduled at `time`; if it is `None`,
    /// the item will be removed from the schedule.
    ///
    /// If `old` is `Some(time)`, the item will be removed from the schedule
    /// (where it is expected to be scheduled at `time`). Then, if `new` is
    /// `Some(time)`, the item will be added to the schedule at `time`.
    ///
    /// If an inconsistency is detected (`old` is `Some(time)` but the item was
    /// not in the schedule at `time`, or `new` is `Some(time)` and the item
    /// is already scheduled at `time`), it is logged and the error is ignored.
    /// This may result in the item appearing twice in the schedule.
    #[tracing::instrument(
        level = "trace",
        skip_all,
        fields(?item, ?old, ?new)
    )]
    pub fn update(&self, item: &T, old: Option<Instant>, new: Option<Instant>) {
        let [old, new] = [old, new].map(|time| {
            time.map(|time| ScheduledItem {
                time,
                item: item.clone(),
            })
        });

        // Lock the schedule.
        let mut schedule = self
            .schedule
            .lock()
            .expect("operations on 'schedule' never panic");

        // Modify the schedule.
        if let Some(old) = old
            && !schedule.remove(&old)
        {
            trace!("Inconsistency detected: `item` was not scheduled as per `old`");
        }
        if let Some(new) = new
            && !schedule.insert(new)
        {
            trace!("Inconsistency detected: `item` was already scheduled as per `new`");
        }

        // Update 'earliest'.
        self.earliest.send_if_modified(|value| {
            let new = schedule.first().map(|item| item.time);
            let old = std::mem::replace(value, new);
            old != new
        });
    }

    /// Drive this scheduler.
    pub async fn run(&self, mut refresh: impl FnMut(Instant, T)) -> Infallible {
        /// Wait until the specified instant, if any.
        async fn wait(deadline: Option<Instant>) {
            if let Some(deadline) = deadline {
                tokio::time::sleep_until(deadline.into()).await
            } else {
                std::future::pending().await
            }
        }

        // A watcher for the 'earliest' field.
        let mut earliest_rx = self.earliest.subscribe();

        loop {
            // Extract the items to refresh.
            let (earliest, now) = {
                // Lock the schedule.
                let mut schedule = self
                    .schedule
                    .lock()
                    .expect("operations on 'schedule' never panic");

                // Extract any items we want to process immediately.
                let latest = Instant::now() + Duration::from_secs(1);
                #[allow(clippy::mutable_key_type)]
                let later = schedule.split_off(&latest);
                #[allow(clippy::mutable_key_type)]
                let now = std::mem::replace(&mut *schedule, later);

                // Update 'earliest'.
                let earliest = schedule.first().map(|item| item.time);
                self.earliest
                    .send(earliest)
                    .expect("'earliest_rx' is a connected receiver");
                earliest_rx.mark_unchanged(); // ignore this change locally.

                (earliest, now)
            };

            // Enqueue the relevant item refreshes.
            for item in now {
                (refresh)(item.time, item.item);
            }

            // Wait for a refresh or a change to the schedule.
            tokio::select! {
                // Watch for external changes to the monitor.
                //
                // NOTE: The sender in 'self' exists so 'Err' is impossible.
                _ = earliest_rx.changed() => {},

                // Wait for the next scheduled item refresh.
                () = wait(earliest) => {},
            }
        }
    }
}

//----------- ScheduledItem ----------------------------------------------------

/// A scheduled item.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ScheduledItem<T> {
    /// The time the item is scheduled for processing at.
    time: Instant,

    /// The item in question.
    item: T,
}

impl<T> AsRef<Instant> for ScheduledItem<T> {
    fn as_ref(&self) -> &Instant {
        &self.time
    }
}

impl<T> Borrow<Instant> for ScheduledItem<T> {
    fn borrow(&self) -> &Instant {
        &self.time
    }
}

impl<T> AsMut<Instant> for ScheduledItem<T> {
    fn as_mut(&mut self) -> &mut Instant {
        &mut self.time
    }
}

impl<T> BorrowMut<Instant> for ScheduledItem<T> {
    fn borrow_mut(&mut self) -> &mut Instant {
        &mut self.time
    }
}
