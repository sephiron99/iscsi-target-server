//! `iscsi-targetd`의 명령줄 인자와 종료 신호.

use std::path::PathBuf;

pub const USAGE: &str = "\
사용법: iscsi-targetd --config <경로> [--check] [--log-level <레벨>]

  --config <경로>     TOML 설정 파일 경로 (필수)
  --check             설정 파일만 검증하고 종료한다
  --log-level <레벨>  trace, debug, info, warn, error 중 하나 (기본 info)
  --help              이 도움말을 출력한다
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
    Run(DaemonOptions),
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonOptions {
    pub config_path: PathBuf,
    pub check_only: bool,
    pub log_level: LogLevel,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "trace" => Self::Trace,
            "debug" => Self::Debug,
            "info" => Self::Info,
            "warn" => Self::Warn,
            "error" => Self::Error,
            _ => return None,
        })
    }

    pub fn tracing_level(self) -> tracing::Level {
        match self {
            Self::Trace => tracing::Level::TRACE,
            Self::Debug => tracing::Level::DEBUG,
            Self::Info => tracing::Level::INFO,
            Self::Warn => tracing::Level::WARN,
            Self::Error => tracing::Level::ERROR,
        }
    }
}

pub fn parse_arguments<I>(arguments: I) -> Result<CliCommand, UsageError>
where
    I: IntoIterator<Item = String>,
{
    let mut config_path: Option<PathBuf> = None;
    let mut check_only = false;
    let mut log_level: Option<LogLevel> = None;
    let mut iterator = arguments.into_iter();
    while let Some(argument) = iterator.next() {
        match argument.as_str() {
            "--help" | "-h" => return Ok(CliCommand::Help),
            "--check" => check_only = true,
            "--config" => {
                let value = iterator
                    .next()
                    .ok_or(UsageError::MissingValue("--config"))?;
                if config_path.replace(PathBuf::from(value)).is_some() {
                    return Err(UsageError::DuplicateOption("--config"));
                }
            }
            "--log-level" => {
                let value = iterator
                    .next()
                    .ok_or(UsageError::MissingValue("--log-level"))?;
                let parsed = LogLevel::parse(&value).ok_or(UsageError::InvalidLogLevel(value))?;
                if log_level.replace(parsed).is_some() {
                    return Err(UsageError::DuplicateOption("--log-level"));
                }
            }
            unknown => return Err(UsageError::UnknownArgument(unknown.to_owned())),
        }
    }
    let config_path = config_path.ok_or(UsageError::MissingConfigPath)?;
    Ok(CliCommand::Run(DaemonOptions {
        config_path,
        check_only,
        log_level: log_level.unwrap_or_default(),
    }))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UsageError {
    #[error("--config <경로> 인자가 필요하다")]
    MissingConfigPath,
    #[error("{0} 인자의 값이 없다")]
    MissingValue(&'static str),
    #[error("{0} 인자가 중복되었다")]
    DuplicateOption(&'static str),
    #[error("알 수 없는 로그 레벨: {0:?}")]
    InvalidLogLevel(String),
    #[error("알 수 없는 인자: {0:?}")]
    UnknownArgument(String),
}

/// Ctrl-C 신호를 기다린다.
pub async fn shutdown_signal() -> Result<(), std::io::Error> {
    tokio::signal::ctrl_c().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> impl Iterator<Item = String> {
        values
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn parses_full_command_line() {
        let command = parse_arguments(arguments(&[
            "--config",
            "/etc/iscsi/target.toml",
            "--check",
            "--log-level",
            "debug",
        ]))
        .unwrap();
        assert_eq!(
            command,
            CliCommand::Run(DaemonOptions {
                config_path: PathBuf::from("/etc/iscsi/target.toml"),
                check_only: true,
                log_level: LogLevel::Debug,
            })
        );
    }

    #[test]
    fn help_takes_precedence_and_defaults_apply() {
        assert_eq!(
            parse_arguments(arguments(&["--help"])).unwrap(),
            CliCommand::Help
        );
        let command = parse_arguments(arguments(&["--config", "target.toml"])).unwrap();
        assert_eq!(
            command,
            CliCommand::Run(DaemonOptions {
                config_path: PathBuf::from("target.toml"),
                check_only: false,
                log_level: LogLevel::Info,
            })
        );
    }

    #[test]
    fn invalid_command_lines_are_rejected() {
        assert_eq!(
            parse_arguments(arguments(&[])).unwrap_err(),
            UsageError::MissingConfigPath
        );
        assert_eq!(
            parse_arguments(arguments(&["--config"])).unwrap_err(),
            UsageError::MissingValue("--config")
        );
        assert_eq!(
            parse_arguments(arguments(&["--config", "a", "--config", "b"])).unwrap_err(),
            UsageError::DuplicateOption("--config")
        );
        assert_eq!(
            parse_arguments(arguments(&["--config", "a", "--log-level", "loud"])).unwrap_err(),
            UsageError::InvalidLogLevel("loud".to_owned())
        );
        assert_eq!(
            parse_arguments(arguments(&["--verbose"])).unwrap_err(),
            UsageError::UnknownArgument("--verbose".to_owned())
        );
    }
}
