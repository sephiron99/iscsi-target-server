//! `tracing` 로그를 창의 로그 영역으로 넘기는 통로와, 화면에 남길 줄을 담는 buffer.
//!
//! 서버 thread들이 쓴 로그 줄은 크기가 정해진 channel에 쌓이고 UI thread가 주기적으로
//! 가져간다. channel이 가득 차면 서버를 멈추지 않고 그 줄을 버리며, 버린 수를 센다.
//! 로그에 무엇을 남기지 않는지는 라이브러리의 `server` 모듈이 정한 그대로다.

use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

/// UI가 가져가기 전에 쌓아 둘 수 있는 로그 줄 수.
const PENDING_LINE_LIMIT: usize = 4096;

/// 전역 `tracing` subscriber를 설치하고 로그를 받는 쪽을 돌려준다.
pub fn install() -> Result<LogReceiver, String> {
    let (sender, receiver) = sync_channel(PENDING_LINE_LIMIT);
    let dropped = Arc::new(AtomicU64::new(0));
    let writer_dropped = dropped.clone();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .with_timer(LocalTimer)
        // 로그 영역이 좁으므로 module 경로는 빼고 시각, level과 내용만 남긴다.
        .with_target(false)
        .with_writer(move || LogWriter {
            sender: sender.clone(),
            dropped: writer_dropped.clone(),
        })
        .try_init()
        .map_err(|error| format!("failed to initialize logging: {error}"))?;
    Ok(LogReceiver { receiver, dropped })
}

/// 로그의 시각을 이 PC의 시간대로 찍는다. 예: `2026-10-12 16:11:38.772 +09:00`.
struct LocalTimer;

impl tracing_subscriber::fmt::time::FormatTime for LocalTimer {
    fn format_time(
        &self,
        writer: &mut tracing_subscriber::fmt::format::Writer<'_>,
    ) -> std::fmt::Result {
        write!(writer, "{}", iscsi_target_server::LocalTimestamp::now())
    }
}

pub struct LogReceiver {
    receiver: Receiver<String>,
    dropped: Arc<AtomicU64>,
}

impl LogReceiver {
    /// 쌓인 로그 줄을 하나 꺼낸다. 기다리지 않는다.
    pub fn try_line(&self) -> Option<String> {
        self.receiver.try_recv().ok()
    }

    /// 지난 호출 이후 channel이 가득 차서 버린 줄 수.
    pub fn take_dropped(&self) -> u64 {
        self.dropped.swap(0, Ordering::Relaxed)
    }
}

/// fmt layer는 event 하나를 한 번의 `write`로 넘긴다. 그 한 줄을 channel에 넣는다.
struct LogWriter {
    sender: SyncSender<String>,
    dropped: Arc<AtomicU64>,
}

impl io::Write for LogWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let line = String::from_utf8_lossy(buffer);
        let line = line.trim_end_matches(['\r', '\n']);
        if !line.is_empty() && self.sender.try_send(line.to_owned()).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// 로그 영역에 남길 최근 줄. 줄 수에 상한이 있어 오래 실행해도 계속 커지지 않는다.
pub struct LogBuffer {
    lines: VecDeque<String>,
    max_lines: usize,
}

/// 줄을 넣은 뒤 화면을 어떻게 고쳐야 하는지.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogUpdate {
    /// 끝에 이 text를 덧붙이면 된다.
    Append(String),
    /// 오래된 줄을 버렸으므로 전체를 이 text로 바꿔야 한다.
    Replace(String),
}

impl LogBuffer {
    pub fn new(max_lines: usize) -> Self {
        Self {
            lines: VecDeque::new(),
            max_lines: max_lines.max(1),
        }
    }

    /// 한 줄을 넣는다. 상한을 넘으면 오래된 쪽 절반을 한꺼번에 버려, 넘칠 때마다
    /// 전체를 다시 그리지 않게 한다.
    pub fn push(&mut self, line: &str) -> LogUpdate {
        self.lines.push_back(line.to_owned());
        if self.lines.len() <= self.max_lines {
            return LogUpdate::Append(format!("{line}\r\n"));
        }
        let keep = (self.max_lines / 2).max(1);
        self.lines.drain(..self.lines.len() - keep);
        LogUpdate::Replace(self.lines.iter().fold(String::new(), |mut text, line| {
            text.push_str(line);
            text.push_str("\r\n");
            text
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn buffer_appends_until_the_limit_then_keeps_the_newest_half() {
        let mut buffer = LogBuffer::new(4);
        for line in ["a", "b", "c", "d"] {
            assert_eq!(buffer.push(line), LogUpdate::Append(format!("{line}\r\n")));
        }
        assert_eq!(
            buffer.push("e"),
            LogUpdate::Replace("d\r\ne\r\n".to_owned())
        );
        assert_eq!(buffer.push("f"), LogUpdate::Append("f\r\n".to_owned()));
        assert_eq!(buffer.push("g"), LogUpdate::Append("g\r\n".to_owned()));
        assert_eq!(
            buffer.push("h"),
            LogUpdate::Replace("g\r\nh\r\n".to_owned())
        );
    }

    #[test]
    fn buffer_with_a_zero_limit_still_keeps_the_last_line() {
        let mut buffer = LogBuffer::new(0);
        assert_eq!(buffer.push("a"), LogUpdate::Append("a\r\n".to_owned()));
        assert_eq!(buffer.push("b"), LogUpdate::Replace("b\r\n".to_owned()));
    }

    #[test]
    fn writer_strips_the_line_ending_and_counts_lines_dropped_when_full() {
        let (sender, receiver) = sync_channel(1);
        let dropped = Arc::new(AtomicU64::new(0));
        let mut writer = LogWriter {
            sender,
            dropped: dropped.clone(),
        };
        let receiver = LogReceiver { receiver, dropped };

        assert_eq!(writer.write(b"first\n").unwrap(), 6);
        assert_eq!(writer.write(b"second\n").unwrap(), 7);
        assert_eq!(writer.write(b"\n").unwrap(), 1);
        assert_eq!(receiver.try_line().as_deref(), Some("first"));
        assert_eq!(receiver.try_line(), None);
        assert_eq!(receiver.take_dropped(), 1);
        assert_eq!(receiver.take_dropped(), 0);

        // 잘못된 UTF-8은 대체 문자로 바꿔 넘긴다.
        writer.write_all(b"bad \xff byte\r\n").unwrap();
        assert_eq!(receiver.try_line().as_deref(), Some("bad \u{fffd} byte"));
    }
}
