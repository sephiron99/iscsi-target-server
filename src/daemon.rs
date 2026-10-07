//! 설정 파일 하나로 Target service를 실행하는 headless daemon 계층 (feature `daemon`).
//!
//! 로그에는 peer 주소, 종료 사유와 오류 요약만 남긴다. Login text, CHAP secret 같은
//! wire payload와 자격 증명은 어떤 로그 레벨에서도 기록하지 않는다.

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use tokio::sync::watch;

use crate::config::{ConfigError, DaemonConfig};
use crate::connection::{ConnectionError, ConnectionStateMachine};
use crate::management::{ManagementError, TargetServiceApi};
use crate::target_service::{
    TargetService, TargetServiceConfig, TargetServiceError, TargetServiceSummary,
};

/// daemon이 여는 Session의 command window (`MaxCmdSN - ExpCmdSN + 1`).
pub const DAEMON_COMMAND_WINDOW: u32 = 32;

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

type ConnectionFactory =
    Box<dyn Fn(SocketAddr) -> Result<ConnectionStateMachine, ConnectionError> + Send + Sync>;

/// 설정에서 만들어져 listen 중인 daemon. [`Daemon::run`]으로 종료까지 실행한다.
pub struct Daemon {
    service: TargetService<ConnectionFactory>,
    api: TargetServiceApi,
}

impl Daemon {
    /// 검증된 설정으로 Target을 등록하고 listener를 bind한다.
    ///
    /// 현재 Login 정책은 Connection마다 하나의 Target에 바인딩되므로 daemon은 단일
    /// Target 설정만 허용한다. Login 시점 `TargetName` 선택은 별도 계획 항목이다.
    pub async fn bind(config: &DaemonConfig) -> Result<Self, DaemonError> {
        config.validate()?;
        let targets = config.targets();
        let [target] = targets else {
            return Err(DaemonError::MultipleTargetsUnsupported(targets.len()));
        };

        let api = TargetServiceApi::new();
        api.add_target(target.clone())?;
        let bound_target = target.name().clone();
        let factory_api = api.clone();
        let tsih_counter = Arc::new(AtomicU32::new(0));
        let factory: ConnectionFactory = Box::new(move |peer| {
            let serial = tsih_counter.fetch_add(1, Ordering::Relaxed);
            let tsih = (serial % u32::from(u16::MAX)) as u16 + 1;
            factory_api
                .create_connection(&bound_target, tsih, DAEMON_COMMAND_WINDOW)
                .map_err(|error| {
                    tracing::warn!(%peer, %error, "connection setup failed");
                    ConnectionError::ServiceUnavailable
                })
        });

        let service = TargetService::bind(
            config.listen().socket_addr(),
            TargetServiceConfig::from(config),
            factory,
        )
        .await?;
        Ok(Self { service, api })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.service.local_addr()
    }

    pub fn api(&self) -> &TargetServiceApi {
        &self.api
    }

    /// `shutdown` future가 완료되거나 service가 스스로 끝날 때까지 실행한다.
    pub async fn run(
        self,
        shutdown: impl Future<Output = ()>,
    ) -> Result<TargetServiceSummary, DaemonError> {
        let (sender, receiver) = watch::channel(false);
        let mut service_task = tokio::spawn(self.service.run(receiver));
        tokio::pin!(shutdown);
        let summary = tokio::select! {
            finished = &mut service_task => finished.map_err(TargetServiceError::from)??,
            () = &mut shutdown => {
                tracing::info!("shutdown requested");
                let _ = sender.send(true);
                (&mut service_task).await.map_err(TargetServiceError::from)??
            }
        };
        Ok(summary)
    }
}

/// Ctrl-C 신호를 기다린다.
pub async fn shutdown_signal() -> Result<(), std::io::Error> {
    tokio::signal::ctrl_c().await
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("daemon은 현재 단일 Target 설정만 지원한다; {0}개가 설정되었다")]
    MultipleTargetsUnsupported(usize),
    #[error(transparent)]
    Management(#[from] ManagementError),
    #[error(transparent)]
    Service(#[from] TargetServiceError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ListenConfig, LunBackendConfig, LunConfig, TargetConfig};
    use crate::login::IscsiName;

    fn arguments(values: &[&str]) -> impl Iterator<Item = String> {
        values
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
            .into_iter()
    }

    fn memory_target(suffix: &str) -> TargetConfig {
        let name = IscsiName::parse(&format!("iqn.2026-07.example.com:{suffix}")).unwrap();
        let mut target = TargetConfig::new(name);
        target
            .add_lun(
                LunConfig::new(
                    0,
                    LunBackendConfig::Memory {
                        block_size: 512,
                        block_count: 8,
                        read_only: false,
                    },
                )
                .unwrap(),
            )
            .unwrap();
        target
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

    #[tokio::test]
    async fn multiple_targets_are_rejected_before_binding() {
        let mut config = DaemonConfig::default();
        config.add_target(memory_target("first")).unwrap();
        config.add_target(memory_target("second")).unwrap();
        let Err(error) = Daemon::bind(&config).await else {
            panic!("expected multi-target rejection");
        };
        assert!(matches!(error, DaemonError::MultipleTargetsUnsupported(2)));
    }

    #[tokio::test]
    async fn daemon_binds_and_stops_on_shutdown_future() {
        let port = {
            let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap().port()
        };
        let mut config = DaemonConfig::new(
            ListenConfig::new("127.0.0.1".parse().unwrap(), port).unwrap(),
            4,
        )
        .unwrap();
        config.add_target(memory_target("daemon")).unwrap();

        let daemon = Daemon::bind(&config).await.unwrap();
        let address = daemon.local_addr().unwrap();
        assert_eq!(address.port(), port);
        assert_eq!(daemon.api().targets().unwrap().len(), 1);

        let summary = daemon.run(async {}).await.unwrap();
        assert_eq!(summary, TargetServiceSummary::default());
    }
}
