use std;
use time;

// TODO(canndrew): Deprecate this function as soon as #[feature(time2)] is stable.
pub fn time_duration_to_std_duration(dur: time::Duration) -> std::time::Duration {
    let millis = dur.num_milliseconds();
    std::time::Duration::from_millis(millis as u64)
}

