use std;
use std::fmt;
use time;

// TODO(canndrew): Deprecate this function as soon as #[feature(time2)] is stable.
pub fn time_duration_to_std_duration(dur: time::Duration) -> std::time::Duration {
    let secs = dur.num_seconds();
    let secs =  if secs < 0 { 0 } else { secs as u64 };
    let nanos = match dur.num_nanoseconds() {
        Some(v) => {
            if v < 0 {
                0
            } else {
                let secs_and_nanos_part = v as u64;
                let secs_par = secs * 1_000_000_000;
                (secs_and_nanos_part - secs_par) as u32
            }
        }
        None => 0,
    };
    std::time::Duration::new(secs, nanos)
}

pub struct DisplaySlice<'a, T: 'a>(pub &'static str, pub &'a [T]);

impl<'a, T> fmt::Display for DisplaySlice<'a, T>
        where T: fmt::Display
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let DisplaySlice(description, slice) = *self;
        let len = slice.len();
        try!(write!(f, "{} {}(s):", len, description));
        for (i, t) in slice.iter().enumerate() {
            try!(write!(f, " ({} of {}) {}", i + 1, len, t));
        }
        Ok(())
    }
}

