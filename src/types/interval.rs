//! Oracle INTERVAL data types
//!
//! Oracle supports two INTERVAL types:
//! - INTERVAL YEAR TO MONTH: stores a period in years and months
//! - INTERVAL DAY TO SECOND: stores a period in days, hours, minutes, seconds

use crate::error::{Error, Result};

/// INTERVAL YEAR TO MONTH
///
/// Represents a period of time measured in years and months.
/// The total months = years * 12 + months.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IntervalYearToMonth {
    /// Total years (can be negative)
    pub years: i32,
    /// Total months (0-11)
    pub months: u8,
}

impl IntervalYearToMonth {
    /// Create a new interval with the given years and months
    pub fn new(years: i32, months: u8) -> Self {
        Self { years, months }
    }

    /// Get the total number of months (years * 12 + months)
    pub fn total_months(&self) -> i64 {
        self.years as i64 * 12 + self.months as i64
    }
}

/// INTERVAL DAY TO SECOND
///
/// Represents a period of time measured in days, hours, minutes, seconds,
/// and fractional seconds (nanoseconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IntervalDayToSecond {
    /// Days (can be negative)
    pub days: i32,
    /// Hours (0-23)
    pub hours: u8,
    /// Minutes (0-59)
    pub minutes: u8,
    /// Seconds (0-59)
    pub seconds: u8,
    /// Nanoseconds (0-999999999)
    pub nanoseconds: u32,
}

impl IntervalDayToSecond {
    /// Create a new interval
    pub fn new(days: i32, hours: u8, minutes: u8, seconds: u8, nanoseconds: u32) -> Self {
        Self {
            days,
            hours,
            minutes,
            seconds,
            nanoseconds,
        }
    }

    /// Get the total duration in seconds (approximate, ignores nanoseconds)
    pub fn total_seconds(&self) -> f64 {
        self.days as f64 * 86400.0
            + self.hours as f64 * 3600.0
            + self.minutes as f64 * 60.0
            + self.seconds as f64
            + self.nanoseconds as f64 / 1_000_000_000.0
    }
}

/// Decode INTERVAL YEAR TO MONTH from Oracle wire format (5 bytes).
///
/// Wire format:
/// - Byte 0: (year / 100) + 60 (high digits of year)
/// - Byte 1: (year % 100) + 100 (low digits of year)
/// - Byte 2: month + 60
/// - Bytes 3-4: unused (always 0)
pub fn decode_interval_ym(bytes: &[u8]) -> Result<IntervalYearToMonth> {
    if bytes.len() < 5 {
        return Err(Error::DataConversionError(
            format!(
                "INTERVAL YEAR TO MONTH requires 5 bytes, got {}",
                bytes.len()
            )
            .into(),
        ));
    }

    let year_high = bytes[0] as i32 - 60;
    let year_low = bytes[1] as i32 - 100;
    let years = year_high * 100 + year_low;
    let months = (bytes[2] as i32 - 60) as u8;

    Ok(IntervalYearToMonth { years, months })
}

/// Encode INTERVAL YEAR TO MONTH to Oracle wire format (5 bytes).
pub fn encode_interval_ym(interval: &IntervalYearToMonth) -> Vec<u8> {
    let mut buf = vec![0u8; 5];
    let y = interval.years;
    buf[0] = ((y / 100) + 60) as u8;
    buf[1] = ((y % 100) + 100) as u8;
    buf[2] = (interval.months + 60) as u8;
    // bytes 3-4 remain 0
    buf
}

/// Decode INTERVAL DAY TO SECOND from Oracle wire format (11 bytes).
///
/// Wire format:
/// - Byte 0: (days / 1000000) + 60
/// - Byte 1: ((days / 10000) % 100) + 100
/// - Byte 2: ((days / 100) % 100) + 100
/// - Byte 3: (days % 100) + 100
/// - Byte 4: hours + 60
/// - Byte 5: minutes + 60
/// - Byte 6: seconds + 60
/// - Bytes 7-10: fractional seconds as big-endian u32 (nanoseconds)
pub fn decode_interval_ds(bytes: &[u8]) -> Result<IntervalDayToSecond> {
    if bytes.len() < 11 {
        return Err(Error::DataConversionError(
            format!(
                "INTERVAL DAY TO SECOND requires 11 bytes, got {}",
                bytes.len()
            )
            .into(),
        ));
    }

    let days = (bytes[0] as i32 - 60) * 1_000_000
        + (bytes[1] as i32 - 100) * 10_000
        + (bytes[2] as i32 - 100) * 100
        + (bytes[3] as i32 - 100);
    let hours = (bytes[4] as i32 - 60) as u8;
    let minutes = (bytes[5] as i32 - 60) as u8;
    let seconds = (bytes[6] as i32 - 60) as u8;
    let nanoseconds = u32::from_be_bytes([bytes[7], bytes[8], bytes[9], bytes[10]]);

    Ok(IntervalDayToSecond {
        days,
        hours,
        minutes,
        seconds,
        nanoseconds,
    })
}

/// Encode INTERVAL DAY TO SECOND to Oracle wire format (11 bytes).
pub fn encode_interval_ds(interval: &IntervalDayToSecond) -> Vec<u8> {
    let mut buf = vec![0u8; 11];
    let d = interval.days;
    buf[0] = ((d / 1_000_000) + 60) as u8;
    buf[1] = (((d / 10_000) % 100) + 100) as u8;
    buf[2] = (((d / 100) % 100) + 100) as u8;
    buf[3] = ((d % 100) + 100) as u8;
    buf[4] = (interval.hours + 60) as u8;
    buf[5] = (interval.minutes + 60) as u8;
    buf[6] = (interval.seconds + 60) as u8;
    buf[7..11].copy_from_slice(&interval.nanoseconds.to_be_bytes());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interval_ym_roundtrip() {
        let orig = IntervalYearToMonth::new(5, 3);
        let encoded = encode_interval_ym(&orig);
        let decoded = decode_interval_ym(&encoded).unwrap();
        assert_eq!(decoded, orig);
    }

    #[test]
    fn test_interval_ym_negative() {
        let orig = IntervalYearToMonth::new(-2, 6);
        let encoded = encode_interval_ym(&orig);
        let decoded = decode_interval_ym(&encoded).unwrap();
        assert_eq!(decoded, orig);
    }

    #[test]
    fn test_interval_ds_roundtrip() {
        let orig = IntervalDayToSecond::new(10, 5, 30, 45, 500_000_000);
        let encoded = encode_interval_ds(&orig);
        let decoded = decode_interval_ds(&encoded).unwrap();
        assert_eq!(decoded, orig);
    }

    #[test]
    fn test_interval_ds_negative_days() {
        let orig = IntervalDayToSecond::new(-3, 12, 0, 0, 0);
        let encoded = encode_interval_ds(&orig);
        let decoded = decode_interval_ds(&encoded).unwrap();
        assert_eq!(decoded, orig);
    }
}
