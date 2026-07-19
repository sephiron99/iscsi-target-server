//! TCP listener와 Connection task의 수명주기 관리.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::net::{TcpListener, ToSocketAddrs};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use crate::config::{DaemonConfig, DEFAULT_MAX_SERVICE_CONNECTIONS};
use crate::connection::{ConnectionCloseReason, ConnectionError, ConnectionStateMachine};
use crate::connection_io::{
    run_connection_with_executor_and_shutdown, BlockingStorageExecutor,
    BlockingStorageExecutorError, ConnectionIoError, DEFAULT_MAX_BLOCKING_STORAGE_OPERATIONS,
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
    active_connections: Arc<AtomicUsize>,
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
            active_connections: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.listener.local_addr()
    }

    /// service task를 시작하고 명시적인 `stop`/`wait` handle을 반환한다.
    pub fn start(self) -> Result<TargetServiceHandle, TargetServiceError> {
        let local_addr = self.local_addr()?;
        let active_connections = self.active_connections.clone();
        let (shutdown, receiver) = watch::channel(false);
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| TargetServiceError::RuntimeUnavailable)?;
        let task = runtime.spawn(self.run(receiver));
        Ok(TargetServiceHandle {
            local_addr,
            shutdown,
            task: Some(task),
            active_connections,
        })
    }

    /// shutdown 값이 `true`가 되거나 sender가 사라질 때 listener를 닫고, active
    /// connection에 Logout을 요청한 뒤 blocking storage 작업까지 drain한다.
    pub async fn run(
        self,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<TargetServiceSummary, TargetServiceError> {
        let mut tasks = JoinSet::new();
        let mut summary = TargetServiceSummary::default();
        let mut listener_error = None;
        let (connection_shutdown, connection_shutdown_receiver) = watch::channel(false);

        while !*shutdown.borrow() {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = self.listener.accept(), if tasks.len() < self.config.max_connections => {
                    let (stream, peer) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            listener_error = Some(error);
                            break;
                        }
                    };
                    summary.accepted_connections = summary.accepted_connections.saturating_add(1);
                    match (self.connection_factory)(peer) {
                        Ok(connection) => {
                            log_connection_accepted(peer);
                            let active = ActiveConnectionGuard::new(self.active_connections.clone());
                            let executor = self.storage_executor.clone();
                            let connection_shutdown = connection_shutdown_receiver.clone();
                            tasks.spawn(async move {
                                let _active = active;
                                let result = run_connection_with_executor_and_shutdown(
                                    stream,
                                    connection,
                                    executor,
                                    connection_shutdown,
                                )
                                .await;
                                (peer, result)
                            });
                        }
                        Err(error) => {
                            log_connection_rejected(peer, &error);
                            summary.failed_connections = summary.failed_connections.saturating_add(1);
                        }
                    }
                }
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    record_completion(completed, &mut summary);
                }
            }
        }

        let _ = connection_shutdown.send(true);
        drop(self.listener);
        log_service_stopping(tasks.len());
        while let Some(completed) = tasks.join_next().await {
            record_completion(Some(completed), &mut summary);
        }
        self.storage_executor.drain().await?;
        debug_assert_eq!(self.active_connections.load(Ordering::Acquire), 0);
        if let Some(error) = listener_error {
            return Err(error.into());
        }
        Ok(summary)
    }
}

/// 실행 중인 Target service의 shutdown과 완료 대기를 소유한다.
#[derive(Debug)]
pub struct TargetServiceHandle {
    local_addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    task: Option<JoinHandle<Result<TargetServiceSummary, TargetServiceError>>>,
    active_connections: Arc<AtomicUsize>,
}

impl TargetServiceHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn active_connections(&self) -> usize {
        self.active_connections.load(Ordering::Acquire)
    }

    /// 새 연결 수락을 중단하고 active connection 및 storage 작업 정리를 기다린다.
    pub async fn stop(mut self) -> Result<TargetServiceSummary, TargetServiceError> {
        let _ = self.shutdown.send(true);
        self.join().await
    }

    /// 외부 오류 등으로 service가 끝날 때까지 기다린다. 직접 종료하려면 `stop`을 쓴다.
    pub async fn wait(mut self) -> Result<TargetServiceSummary, TargetServiceError> {
        self.join().await
    }

    async fn join(&mut self) -> Result<TargetServiceSummary, TargetServiceError> {
        let task = self
            .task
            .take()
            .ok_or(TargetServiceError::MissingServiceTask)?;
        task.await?
    }
}

impl Drop for TargetServiceHandle {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

struct ActiveConnectionGuard(Arc<AtomicUsize>);

impl ActiveConnectionGuard {
    fn new(active: Arc<AtomicUsize>) -> Self {
        active.fetch_add(1, Ordering::AcqRel);
        Self(active)
    }
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

type ConnectionOutcome = (SocketAddr, Result<ConnectionCloseReason, ConnectionIoError>);

fn record_completion(
    completed: Option<Result<ConnectionOutcome, tokio::task::JoinError>>,
    summary: &mut TargetServiceSummary,
) {
    match completed {
        Some(Ok((peer, Ok(reason)))) => {
            log_connection_closed(peer, reason);
            summary.completed_connections = summary.completed_connections.saturating_add(1);
        }
        Some(Ok((peer, Err(error)))) => {
            log_connection_failed(peer, &error);
            summary.failed_connections = summary.failed_connections.saturating_add(1);
        }
        Some(Err(error)) if error.is_cancelled() => {
            summary.aborted_connections = summary.aborted_connections.saturating_add(1);
        }
        Some(Err(error)) => {
            log_connection_panicked(&error);
            summary.failed_connections = summary.failed_connections.saturating_add(1);
        }
        None => {}
    }
}

// 로그에는 peer 주소, 종료 사유와 오류 요약만 남긴다. Login text와 자격 증명 등
// wire payload는 어떤 레벨에서도 기록하지 않는다.

fn log_connection_accepted(peer: SocketAddr) {
    #[cfg(feature = "tracing")]
    tracing::info!(%peer, "connection accepted");
    #[cfg(not(feature = "tracing"))]
    let _ = peer;
}

fn log_connection_rejected(peer: SocketAddr, error: &ConnectionError) {
    #[cfg(feature = "tracing")]
    tracing::warn!(%peer, %error, "connection setup rejected");
    #[cfg(not(feature = "tracing"))]
    let _ = (peer, error);
}

fn log_connection_closed(peer: SocketAddr, reason: ConnectionCloseReason) {
    #[cfg(feature = "tracing")]
    tracing::info!(%peer, ?reason, "connection closed");
    #[cfg(not(feature = "tracing"))]
    let _ = (peer, reason);
}

fn log_connection_failed(peer: SocketAddr, error: &ConnectionIoError) {
    #[cfg(feature = "tracing")]
    tracing::warn!(%peer, %error, "connection failed");
    #[cfg(not(feature = "tracing"))]
    let _ = (peer, error);
}

fn log_connection_panicked(error: &tokio::task::JoinError) {
    #[cfg(feature = "tracing")]
    tracing::error!(%error, "connection task panicked");
    #[cfg(not(feature = "tracing"))]
    let _ = error;
}

fn log_service_stopping(active_connections: usize) {
    #[cfg(feature = "tracing")]
    tracing::info!(active_connections, "service stopping; draining connections");
    #[cfg(not(feature = "tracing"))]
    let _ = active_connections;
}

#[derive(Debug, thiserror::Error)]
pub enum TargetServiceError {
    #[error("max_connections must be greater than zero")]
    InvalidConnectionLimit,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    BlockingStorage(#[from] BlockingStorageExecutorError),
    #[error("Target service task failed")]
    ServiceTask(#[from] tokio::task::JoinError),
    #[error("Target service task has already been joined")]
    MissingServiceTask,
    #[error("Target service start requires an active Tokio runtime")]
    RuntimeUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::codec::{Decoder, Encoder};

    use crate::codec::IscsiCodec;
    use crate::control::LogoutRequest;
    use crate::login::{IscsiName, LoginRequest, TextParameters};
    use crate::login_policy::TargetLoginPolicy;
    use crate::opcode::LoginStage;
    use crate::target_login::TargetLoginProcessor;
    use crate::Pdu;

    async fn exchange(
        stream: &mut tokio::net::TcpStream,
        codec: &mut IscsiCodec,
        input: &mut BytesMut,
        pdu: Pdu,
    ) -> Pdu {
        let mut wire = BytesMut::new();
        codec.encode(pdu, &mut wire).unwrap();
        stream.write_all(&wire).await.unwrap();
        receive(stream, codec, input).await
    }

    async fn receive(
        stream: &mut tokio::net::TcpStream,
        codec: &mut IscsiCodec,
        input: &mut BytesMut,
    ) -> Pdu {
        loop {
            if let Some(frame) = codec.decode(input).unwrap() {
                return frame.pdu;
            }
            assert_ne!(stream.read_buf(input).await.unwrap(), 0);
        }
    }

    fn login_request(stage: LoginStage, next_stage: LoginStage, text: &[u8], cmd_sn: u32) -> Pdu {
        Pdu::LoginRequest(LoginRequest {
            transit: true,
            continue_: false,
            current_stage: stage,
            next_stage,
            version_max: 0,
            version_min: 0,
            isid: [1, 2, 3, 4, 5, 6],
            tsih: 0,
            initiator_task_tag: 1,
            cid: 0x1234,
            cmd_sn,
            exp_stat_sn: 0,
            params: TextParameters::parse(text),
        })
    }

    #[tokio::test]
    async fn start_and_stop_request_logout_and_clean_up_active_connection() {
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
        let handle = service.start().unwrap();
        let address = handle.local_addr();

        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut codec = IscsiCodec::new();
        let mut input = BytesMut::new();
        let security = exchange(
            &mut stream,
            &mut codec,
            &mut input,
            login_request(
                LoginStage::Security,
                LoginStage::Operational,
                b"InitiatorName=iqn.2024-01.com.example:initiator\0TargetName=iqn.2024-01.com.example:target\0AuthMethod=None\0",
                10,
            ),
        )
        .await;
        assert!(matches!(security, Pdu::LoginResponse(_)));
        let operational = exchange(
            &mut stream,
            &mut codec,
            &mut input,
            login_request(LoginStage::Operational, LoginStage::FullFeature, b"", 11),
        )
        .await;
        assert!(matches!(operational, Pdu::LoginResponse(_)));
        assert_eq!(handle.active_connections(), 1);

        let active_connections = handle.active_connections.clone();
        let stopping = tokio::spawn(handle.stop());
        let Pdu::AsyncMessage(request) = receive(&mut stream, &mut codec, &mut input).await else {
            panic!("expected target-initiated Logout request");
        };
        assert_eq!(request.async_event, 1);
        let logout = exchange(
            &mut stream,
            &mut codec,
            &mut input,
            Pdu::LogoutRequest(LogoutRequest {
                immediate: true,
                reason_code: 0,
                initiator_task_tag: 9,
                cid: 0x1234,
                cmd_sn: 11,
                exp_stat_sn: request.stat_sn.wrapping_add(1),
            }),
        )
        .await;
        assert!(matches!(logout, Pdu::LogoutResponse(_)));

        let summary = stopping.await.unwrap().unwrap();
        assert_eq!(summary.accepted_connections, 1);
        assert_eq!(summary.completed_connections, 1);
        assert_eq!(summary.failed_connections, 0);
        assert_eq!(summary.aborted_connections, 0);
        assert_eq!(active_connections.load(Ordering::Acquire), 0);
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

    #[tokio::test]
    async fn excessive_blocking_storage_limit_is_rejected_before_bind() {
        let max_supported = tokio::sync::Semaphore::MAX_PERMITS.min(u32::MAX as usize);
        let invalid = max_supported.saturating_add(1);
        let result = TargetService::bind(
            "127.0.0.1:0",
            TargetServiceConfig {
                max_connections: 1,
                max_blocking_storage_operations: invalid,
            },
            |_| unreachable!(),
        )
        .await;
        assert!(matches!(
            result,
            Err(TargetServiceError::BlockingStorage(
                BlockingStorageExecutorError::LimitTooLarge { value, max }
            )) if value == invalid && max == max_supported
        ));
    }
}
