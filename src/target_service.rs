//! TCP listener와 Connection task의 수명주기 관리.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, ToSocketAddrs};
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::config::{DaemonConfig, DEFAULT_MAX_SERVICE_CONNECTIONS};
use crate::connection::{ConnectionError, ConnectionStateMachine};
use crate::connection_io::{
    run_connection_with_executor, BlockingStorageExecutor, BlockingStorageExecutorError,
    DEFAULT_MAX_BLOCKING_STORAGE_OPERATIONS,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetServiceConfig {
    pub max_connections: usize,
    pub max_blocking_storage_operations: usize,
}

impl Default for TargetServiceConfig {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_SERVICE_CONNECTIONS,
            max_blocking_storage_operations: DEFAULT_MAX_BLOCKING_STORAGE_OPERATIONS,
        }
    }
}

impl From<&DaemonConfig> for TargetServiceConfig {
    fn from(config: &DaemonConfig) -> Self {
        Self {
            max_connections: config.max_connections(),
            max_blocking_storage_operations: config.max_blocking_storage_operations(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TargetServiceSummary {
    pub accepted_connections: u64,
    pub completed_connections: u64,
    pub failed_connections: u64,
    pub aborted_connections: u64,
}

/// peer 주소마다 독립적인 Connection 상태 머신을 만드는 TCP Target service.
pub struct TargetService<F> {
    listener: TcpListener,
    config: TargetServiceConfig,
    connection_factory: Arc<F>,
    storage_executor: BlockingStorageExecutor,
}

impl<F> TargetService<F>
where
    F: Fn(SocketAddr) -> Result<ConnectionStateMachine, ConnectionError> + Send + Sync + 'static,
{
    pub async fn bind(
        address: impl ToSocketAddrs,
        config: TargetServiceConfig,
        connection_factory: F,
    ) -> Result<Self, TargetServiceError> {
        if config.max_connections == 0 {
            return Err(TargetServiceError::InvalidConnectionLimit);
        }
        let storage_executor =
            BlockingStorageExecutor::new(config.max_blocking_storage_operations)?;
        Ok(Self {
            listener: TcpListener::bind(address).await?,
            config,
            connection_factory: Arc::new(connection_factory),
            storage_executor,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.listener.local_addr()
    }

    /// shutdown 값이 `true`가 되거나 sender가 사라질 때 listener를 닫고
    /// 남은 connection task를 취소한 뒤 완료 통계를 반환한다.
    pub async fn run(
        self,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<TargetServiceSummary, TargetServiceError> {
        let mut tasks = JoinSet::new();
        let mut summary = TargetServiceSummary::default();

        while !*shutdown.borrow() {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = self.listener.accept(), if tasks.len() < self.config.max_connections => {
                    let (stream, peer) = accepted?;
                    summary.accepted_connections = summary.accepted_connections.saturating_add(1);
                    match (self.connection_factory)(peer) {
                        Ok(connection) => {
                            tasks.spawn(run_connection_with_executor(
                                stream,
                                connection,
                                self.storage_executor.clone(),
                            ));
                        }
                        Err(_) => {
                            summary.failed_connections = summary.failed_connections.saturating_add(1);
                        }
                    }
                }
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    record_completion(completed, &mut summary);
                }
            }
        }

        // shutdown과 동시에 이미 끝난 task는 aborted로 잘못 집계하지 않는다.
        while let Some(completed) = tasks.try_join_next() {
            record_completion(Some(completed), &mut summary);
        }
        summary.aborted_connections = summary
            .aborted_connections
            .saturating_add(u64::try_from(tasks.len()).unwrap_or(u64::MAX));
        tasks.shutdown().await;
        Ok(summary)
    }
}

fn record_completion<T, E>(
    completed: Option<Result<Result<T, E>, tokio::task::JoinError>>,
    summary: &mut TargetServiceSummary,
) {
    match completed {
        Some(Ok(Ok(_))) => {
            summary.completed_connections = summary.completed_connections.saturating_add(1);
        }
        Some(Ok(Err(_))) | Some(Err(_)) => {
            summary.failed_connections = summary.failed_connections.saturating_add(1);
        }
        None => {}
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TargetServiceError {
    #[error("max_connections must be greater than zero")]
    InvalidConnectionLimit,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    BlockingStorage(#[from] BlockingStorageExecutorError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::codec::{Decoder, Encoder};

    use crate::codec::IscsiCodec;
    use crate::login::{IscsiName, LoginRequest, TextParameters};
    use crate::login_policy::TargetLoginPolicy;
    use crate::opcode::LoginStage;
    use crate::target_login::TargetLoginProcessor;
    use crate::Pdu;

    #[tokio::test]
    async fn listener_binds_cid_runs_connection_task_and_cleans_it_up() {
        let target_name = IscsiName::parse("iqn.2024-01.com.example:target").unwrap();
        let service = TargetService::bind(
            "127.0.0.1:0",
            TargetServiceConfig {
                max_connections: 2,
                ..TargetServiceConfig::default()
            },
            move |_| {
                let mut policy = TargetLoginPolicy::default();
                policy.set_target_name(target_name.clone());
                ConnectionStateMachine::new_unbound(TargetLoginProcessor::new(policy, 1), 4)
            },
        )
        .await
        .unwrap();
        let address = service.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(service.run(shutdown_rx));

        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut codec = IscsiCodec::new();
        let mut wire = BytesMut::new();
        codec
            .encode(
                Pdu::LoginRequest(LoginRequest {
                    transit: true,
                    continue_: false,
                    current_stage: LoginStage::Security,
                    next_stage: LoginStage::Operational,
                    version_max: 0,
                    version_min: 0,
                    isid: [1, 2, 3, 4, 5, 6],
                    tsih: 0,
                    initiator_task_tag: 1,
                    cid: 0x1234,
                    cmd_sn: 10,
                    exp_stat_sn: 0,
                    params: TextParameters::parse(
                        b"InitiatorName=iqn.2024-01.com.example:initiator\0TargetName=iqn.2024-01.com.example:target\0AuthMethod=None\0",
                    ),
                }),
                &mut wire,
            )
            .unwrap();
        stream.write_all(&wire).await.unwrap();

        let mut input = BytesMut::new();
        loop {
            if let Some(frame) = codec.decode(&mut input).unwrap() {
                assert!(matches!(frame.pdu, Pdu::LoginResponse(_)));
                break;
            }
            assert_ne!(stream.read_buf(&mut input).await.unwrap(), 0);
        }

        shutdown_tx.send(true).unwrap();
        let summary = server.await.unwrap().unwrap();
        assert_eq!(summary.accepted_connections, 1);
        assert_eq!(summary.completed_connections, 0);
        assert_eq!(summary.failed_connections, 0);
        assert_eq!(summary.aborted_connections, 1);
    }

    #[tokio::test]
    async fn zero_connection_limit_is_rejected_before_bind() {
        let result = TargetService::bind(
            "127.0.0.1:0",
            TargetServiceConfig {
                max_connections: 0,
                ..TargetServiceConfig::default()
            },
            |_| unreachable!(),
        )
        .await;
        assert!(matches!(
            result,
            Err(TargetServiceError::InvalidConnectionLimit)
        ));
    }

    #[tokio::test]
    async fn zero_blocking_storage_limit_is_rejected_before_bind() {
        let result = TargetService::bind(
            "127.0.0.1:0",
            TargetServiceConfig {
                max_connections: 1,
                max_blocking_storage_operations: 0,
            },
            |_| unreachable!(),
        )
        .await;
        assert!(matches!(
            result,
            Err(TargetServiceError::BlockingStorage(
                BlockingStorageExecutorError::InvalidLimit
            ))
        ));
    }
}
