//! 설정 하나로 Target service를 띄우고 내리는 계층 (feature `codec`).
//!
//! 명령줄 daemon과 GUI가 함께 쓰는 진입점이다. 인자 처리, 로그 출력 설정, 종료 신호
//! 같은 실행 파일의 일은 여기에 두지 않는다.
//!
//! 로그에는 peer 주소, 종료 사유와 오류 요약만 남긴다. Login text, CHAP secret 같은
//! wire payload와 자격 증명은 어떤 로그 레벨에서도 기록하지 않는다.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use tokio::sync::watch;

use crate::config::{ConfigError, DaemonConfig};
use crate::connection::{ConnectionError, ConnectionStateMachine};
use crate::management::{ManagementError, TargetServiceApi};
use crate::target_service::{
    TargetService, TargetServiceConfig, TargetServiceError, TargetServiceSummary,
};

/// daemon이 여는 Session의 command window (`MaxCmdSN - ExpCmdSN + 1`).
pub const DAEMON_COMMAND_WINDOW: u32 = 32;

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
    /// daemon은 단일 Target만 허용한다. Connection은 수락 시점에 그 Target에
    /// 바인딩되고 Login의 `TargetName`은 일치 여부만 검증한다. 원본 iSCSIConsole과
    /// 달리 `TargetName`으로 Target을 선택하는 다중 Target은 지원하지 않는다.
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
                    #[cfg(feature = "tracing")]
                    tracing::warn!(%peer, %error, "connection setup failed");
                    #[cfg(not(feature = "tracing"))]
                    let _ = (peer, error);
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
                #[cfg(feature = "tracing")]
                tracing::info!("shutdown requested");
                let _ = sender.send(true);
                (&mut service_task).await.map_err(TargetServiceError::from)??
            }
        };
        Ok(summary)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("daemon은 단일 Target 설정만 지원한다; {0}개가 설정되었다")]
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
