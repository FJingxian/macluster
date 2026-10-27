use std::{
    sync::{Arc, Condvar, Mutex},
    time::Instant,
};

struct SignalState {
    generation: Mutex<u64>,
    condition: Condvar,
}

/// A coalescing wake signal shared by controller event producers.
#[derive(Clone)]
pub struct RuntimeSignal {
    state: Arc<SignalState>,
}

/// Waits for a signal generation change or the next controller deadline.
pub struct RuntimeWaiter {
    state: Arc<SignalState>,
    observed_generation: u64,
}

impl RuntimeSignal {
    pub fn pair() -> (Self, RuntimeWaiter) {
        let state = Arc::new(SignalState {
            generation: Mutex::new(0),
            condition: Condvar::new(),
        });
        (
            Self {
                state: Arc::clone(&state),
            },
            RuntimeWaiter {
                state,
                observed_generation: 0,
            },
        )
    }

    /// Record one event and wake the controller if it is waiting.
    /// Multiple events can share one wake; durable state remains authoritative.
    pub fn notify(&self) {
        let mut generation = self
            .state
            .generation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *generation = generation.wrapping_add(1);
        self.state.condition.notify_one();
    }
}

impl RuntimeWaiter {
    /// Wait until a producer signals or the supplied monotonic deadline arrives.
    /// Returns true when at least one generation change was observed.
    pub fn wait_until(&mut self, deadline: Instant) -> bool {
        let mut generation = self
            .state
            .generation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *generation != self.observed_generation {
            self.observed_generation = *generation;
            return true;
        }

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            let (next_generation, timeout) = self
                .state
                .condition
                .wait_timeout(generation, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            generation = next_generation;
            if *generation != self.observed_generation {
                self.observed_generation = *generation;
                return true;
            }
            if timeout.timed_out() {
                return false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::RuntimeSignal;

    #[test]
    fn an_event_before_wait_is_not_lost_and_bursts_coalesce() {
        let (signal, mut waiter) = RuntimeSignal::pair();

        for _ in 0..10_000 {
            signal.notify();
        }

        assert!(waiter.wait_until(Instant::now() + Duration::from_secs(1)));
        assert!(!waiter.wait_until(Instant::now()));
    }

    #[test]
    fn waiter_returns_at_the_deadline_without_a_notification() {
        let (_signal, mut waiter) = RuntimeSignal::pair();
        let start = Instant::now();

        assert!(!waiter.wait_until(start + Duration::from_millis(20)));
        assert!(start.elapsed() >= Duration::from_millis(10));
    }
}
