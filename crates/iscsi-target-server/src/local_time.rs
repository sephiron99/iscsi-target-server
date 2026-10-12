//! 이 PC의 시간대로 본 현재 시각.
//!
//! 로그의 시각을 현지 시간으로 찍는 데 쓴다. 표준 라이브러리는 시각을 1970년부터의
//! 초로만 주고 시간대를 모르므로, Windows에 현지 시각을 묻는다.
//!
//! 로그 형식을 정하는 `tracing-subscriber`는 실행 파일의 의존성이라 이 모듈은 그것을
//! 모른다. 실행 파일이 [`LocalTimestamp::now`]를 자기 로그 설정에 끼워 넣는다.

use std::fmt;

/// 현지 시각과, 그 시각이 UTC보다 얼마나 앞서는지.
///
/// `Display`는 `2026-10-12 16:11:38.772 +09:00` 모양으로 적는다. offset을 함께 적어
/// 로그를 다른 시간대에서 읽어도 시각이 모호하지 않다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalTimestamp {
    pub year: u16,
    /// 1월이 1이다.
    pub month: u16,
    pub day: u16,
    pub hour: u16,
    pub minute: u16,
    pub second: u16,
    pub millisecond: u16,
    /// 현지 시각에서 UTC를 뺀 값(분). 한국은 540이다.
    pub utc_offset_minutes: i32,
}

impl LocalTimestamp {
    /// 지금의 현지 시각.
    #[cfg(windows)]
    pub fn now() -> Self {
        // 시각은 한 번만 읽고, 그 UTC 시각을 Windows가 현지 시각으로 바꾸게 한다. 두
        // 값이 정확히 같은 순간이라 차이가 곧 offset이다. 현지 시각과 UTC를 따로 읽으면
        // 그 사이에 시계가 넘어가거나 고쳐졌을 때 offset이 틀어진다.
        let utc = winsafe::GetSystemTime();
        let Ok(local) = winsafe::SystemTimeToTzSpecificLocalTime(None, &utc) else {
            // 변환하지 못하면 틀린 시간대를 지어내지 않고 UTC임을 밝혀 찍는다.
            return Self {
                year: utc.wYear,
                month: utc.wMonth,
                day: utc.wDay,
                hour: utc.wHour,
                minute: utc.wMinute,
                second: utc.wSecond,
                millisecond: utc.wMilliseconds,
                utc_offset_minutes: 0,
            };
        };
        Self {
            year: local.wYear,
            month: local.wMonth,
            day: local.wDay,
            hour: local.wHour,
            minute: local.wMinute,
            second: local.wSecond,
            millisecond: local.wMilliseconds,
            utc_offset_minutes: utc_offset_minutes(
                (local.wYear, local.wMonth, local.wDay),
                local.wHour * 60 + local.wMinute,
                (utc.wYear, utc.wMonth, utc.wDay),
                utc.wHour * 60 + utc.wMinute,
            ),
        }
    }

    /// 지금의 시각. Windows가 아닌 host에서는 시간대를 묻지 않고 UTC로 돌려준다.
    /// 지원 target이 아니며 개발 중의 build와 test를 위한 것이다.
    #[cfg(not(windows))]
    pub fn now() -> Self {
        let elapsed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let mut timestamp = Self::from_unix_seconds(elapsed.as_secs());
        timestamp.millisecond = elapsed.subsec_millis() as u16;
        timestamp
    }

    /// 1970-01-01 00:00 UTC부터의 초를 UTC 날짜와 시각으로 바꾼다. 날짜 계산은 Howard
    /// Hinnant의 `civil_from_days` 방식이다.
    pub fn from_unix_seconds(unix_seconds: u64) -> Self {
        // 0000-03-01을 기준으로 삼으면 윤일이 한 해의 끝에 온다.
        let days = unix_seconds / 86_400 + 719_468;
        let era = days / 146_097;
        let day_of_era = days % 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        // 3월을 0으로 세는 달.
        let shifted_month = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
        let month = if shifted_month < 10 {
            shifted_month + 3
        } else {
            shifted_month - 9
        };
        let year = year_of_era + era * 400 + u64::from(month <= 2);
        let second_of_day = unix_seconds % 86_400;
        Self {
            // 연도는 u16을 넘지 않는 범위에서만 쓰인다. 넘으면 끝 값에 머문다.
            year: u16::try_from(year).unwrap_or(u16::MAX),
            month: month as u16,
            day: day as u16,
            hour: (second_of_day / 3_600) as u16,
            minute: (second_of_day % 3_600 / 60) as u16,
            second: (second_of_day % 60) as u16,
            millisecond: 0,
            utc_offset_minutes: 0,
        }
    }
}

impl fmt::Display for LocalTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sign = if self.utc_offset_minutes < 0 {
            '-'
        } else {
            '+'
        };
        let offset = self.utc_offset_minutes.unsigned_abs();
        write!(
            formatter,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03} {sign}{:02}:{:02}",
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
            self.millisecond,
            offset / 60,
            offset % 60
        )
    }
}

/// 같은 순간의 현지 시각과 UTC 시각에서 offset(분)을 구한다.
///
/// 각 시각은 (연, 월, 일)과 그날 자정부터의 분으로 받는다. 두 날짜는 같거나 하루
/// 차이이므로 달력 계산 없이 앞뒤만 비교한다. 초 이하는 두 시각에서 같으므로 보지
/// 않는다.
#[cfg_attr(not(windows), allow(dead_code))]
fn utc_offset_minutes(
    local_date: (u16, u16, u16),
    local_minute_of_day: u16,
    utc_date: (u16, u16, u16),
    utc_minute_of_day: u16,
) -> i32 {
    const MINUTES_PER_DAY: i32 = 24 * 60;
    let day_difference = match local_date.cmp(&utc_date) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    };
    day_difference * MINUTES_PER_DAY + i32::from(local_minute_of_day) - i32::from(utc_minute_of_day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minute(hour: u16, minute: u16) -> u16 {
        hour * 60 + minute
    }

    #[test]
    fn timestamp_is_written_with_milliseconds_and_the_utc_offset() {
        let mut timestamp = LocalTimestamp {
            year: 2026,
            month: 10,
            day: 12,
            hour: 16,
            minute: 11,
            second: 38,
            millisecond: 772,
            utc_offset_minutes: 540,
        };
        assert_eq!(timestamp.to_string(), "2026-10-12 16:11:38.772 +09:00");

        timestamp.hour = 3;
        timestamp.minute = 4;
        timestamp.second = 5;
        timestamp.millisecond = 6;
        timestamp.month = 1;
        timestamp.day = 2;
        timestamp.utc_offset_minutes = -210;
        assert_eq!(timestamp.to_string(), "2026-01-02 03:04:05.006 -03:30");

        timestamp.utc_offset_minutes = 0;
        assert_eq!(timestamp.to_string(), "2026-01-02 03:04:05.006 +00:00");
    }

    #[test]
    fn offset_is_the_difference_between_local_and_utc_wall_clocks() {
        let day = (2026, 10, 12);
        // 서울: 16:11은 UTC 07:11
        assert_eq!(
            utc_offset_minutes(day, minute(16, 11), day, minute(7, 11)),
            540
        );
        // 뉴욕(여름): 03:11은 UTC 07:11
        assert_eq!(
            utc_offset_minutes(day, minute(3, 11), day, minute(7, 11)),
            -240
        );
        // 네팔: +05:45
        assert_eq!(
            utc_offset_minutes(day, minute(12, 56), day, minute(7, 11)),
            345
        );
        assert_eq!(
            utc_offset_minutes(day, minute(7, 11), day, minute(7, 11)),
            0
        );
    }

    #[test]
    fn offset_is_right_when_local_and_utc_fall_on_different_days() {
        // 서울 10월 13일 02:00은 UTC 10월 12일 17:00
        assert_eq!(
            utc_offset_minutes((2026, 10, 13), minute(2, 0), (2026, 10, 12), minute(17, 0)),
            540
        );
        // 호놀룰루 12월 31일 20:00은 UTC 다음 해 1월 1일 06:00
        assert_eq!(
            utc_offset_minutes((2026, 12, 31), minute(20, 0), (2027, 1, 1), minute(6, 0)),
            -600
        );
        // 달이 바뀌는 날: 키리바시 +14:00
        assert_eq!(
            utc_offset_minutes((2026, 3, 1), minute(1, 0), (2026, 2, 28), minute(11, 0)),
            840
        );
    }

    #[test]
    fn offset_is_right_at_the_instant_either_date_changes() {
        // 현지 날짜가 막 바뀐 순간: 서울 10월 13일 00:00은 UTC 10월 12일 15:00
        assert_eq!(
            utc_offset_minutes((2026, 10, 13), minute(0, 0), (2026, 10, 12), minute(15, 0)),
            540
        );
        // 그 직전: 서울 10월 12일 23:59는 UTC 10월 12일 14:59
        assert_eq!(
            utc_offset_minutes(
                (2026, 10, 12),
                minute(23, 59),
                (2026, 10, 12),
                minute(14, 59)
            ),
            540
        );
        // UTC 날짜가 막 바뀐 순간: 서울 10월 13일 09:00은 UTC 10월 13일 00:00
        assert_eq!(
            utc_offset_minutes((2026, 10, 13), minute(9, 0), (2026, 10, 13), minute(0, 0)),
            540
        );
        // 그 직전: 서울 10월 13일 08:59는 UTC 10월 12일 23:59
        assert_eq!(
            utc_offset_minutes(
                (2026, 10, 13),
                minute(8, 59),
                (2026, 10, 12),
                minute(23, 59)
            ),
            540
        );
    }

    #[test]
    fn unix_seconds_become_utc_dates_across_leap_years() {
        let date = |seconds| {
            let timestamp = LocalTimestamp::from_unix_seconds(seconds);
            (timestamp.year, timestamp.month, timestamp.day)
        };
        assert_eq!(date(0), (1970, 1, 1));
        assert_eq!(date(31 * 86_400 - 1), (1970, 1, 31));
        assert_eq!(date(31 * 86_400), (1970, 2, 1));
        assert_eq!(date(951_782_400), (2000, 2, 29));
        assert_eq!(date(951_868_800), (2000, 3, 1));
        assert_eq!(date(1_704_067_199), (2023, 12, 31));
        assert_eq!(date(1_704_067_200), (2024, 1, 1));
        // 2100년은 윤년이 아니다.
        assert_eq!(date(4_107_456_000), (2100, 2, 28));
        assert_eq!(date(4_107_542_400), (2100, 3, 1));

        // 2026-10-12 07:11:38 UTC
        assert_eq!(
            LocalTimestamp::from_unix_seconds(1_791_789_098).to_string(),
            "2026-10-12 07:11:38.000 +00:00"
        );
    }

    #[test]
    fn now_is_a_plausible_local_time() {
        let now = LocalTimestamp::now();
        assert!(now.year >= 2026);
        assert!((1..=12).contains(&now.month));
        assert!((1..=31).contains(&now.day));
        assert!(now.hour < 24 && now.minute < 60 && now.second < 60);
        assert!(now.millisecond < 1000);
        assert!((-12 * 60..=14 * 60).contains(&now.utc_offset_minutes));
        assert_eq!(now.utc_offset_minutes % 15, 0);
        println!("now: {now}");
    }
}
