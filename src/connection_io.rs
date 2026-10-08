//! 선택적 Tokio stream adapter for [`ConnectionStateMachine`].

use std::sync::Arc;

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{watch, Semaphore};
use tokio::time::{timeout, Instant};
use tokio_util::codec::{Decoder, Encoder};

use crate::codec::IscsiCodec;
pub use crate::config::DEFAULT_MAX_BLOCKING_STORAGE_OPERATIONS;
use crate::connection::{
    ConnectionCloseReason, ConnectionError, ConnectionPhase, ConnectionStateMachine,
    ConnectionTimeoutKind,
};
use crate::error::CodecError;
use crate::frame::FrameConfig;
use crate::{Pdu, BHS_LEN};

const READ_CHUNK_LENGTH: usize = 8192;

#[derive(Debug, Clone)]
/// 동기 backend 작업을 Tokio blocking pool로 보내고 service 전체 동시 실행 수를 제한한다.
/// 시작된 `spawn_blocking` 작업은 취소할 수 없으므로 graceful shutdown은 permit 회수와
/// 진행 중 작업의 완료를 별도로 기다려야 한다.
pub struct BlockingStorageExecutor {
    permits: Arc<Semaphore>,
    max_operations: usize,
}

impl BlockingStorageExecutor {
    pub fn new(max_operations: usize) -> Result<Self, BlockingStorageExecutorError> {
        if max_operations == 0 {
            return Err(BlockingStorageExecutorError::InvalidLimit);
        }
        let max_supported = Semaphore::MAX_PERMITS.min(u32::MAX as usize);
        if max_operations > max_supported {
            return Err(BlockingStorageExecutorError::LimitTooLarge {
                value: max_operations,
                max: max_supported,
            });
        }
        Ok(Self {
            permits: Arc::new(Semaphore::new(max_operations)),
            max_operations,
        })
    }

    pub fn max_operations(&self) -> usize {
        self.max_operations
    }

    /// 모든 producer를 먼저 중단한 뒤 진행 중인 blocking 작업이 permit을 반환할 때까지
    /// 기다린다. 새 작업과 동시에 호출하면 새 작업도 drain 대상에 포함될 수 있다.
    pub async fn drain(&self) -> Result<(), BlockingStorageExecutorError> {
        let count = u32::try_from(self.max_operations).map_err(|_| {
            BlockingStorageExecutorError::LimitTooLarge {
                value: self.max_operations,
                max: u32::MAX as usize,
            }
        })?;
        let permits = self
            .permits
            .clone()
            .acquire_many_owned(count)
            .await
            .map_err(|_| BlockingStorageExecutorError::Closed)?;
        drop(permits);
        Ok(())
    }

    async fn receive(
        &self,
        mut connection: ConnectionStateMachine,
        pdu: Pdu,
    ) -> Result<
        (
            ConnectionStateMachine,
            Result<crate::ConnectionOutput, ConnectionError>,
        ),
        ConnectionIoError,
    > {
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ConnectionIoError::StorageExecutorClosed)?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let result = connection.receive(pdu);
            (connection, result)
        })
        .await
        .map_err(ConnectionIoError::StorageTask)
    }
}

impl Default for BlockingStorageExecutor {
    fn default() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(DEFAULT_MAX_BLOCKING_STORAGE_OPERATIONS)),
            max_operations: DEFAULT_MAX_BLOCKING_STORAGE_OPERATIONS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BlockingStorageExecutorError {
    #[error("max blocking storage operations must be greater than zero")]
    InvalidLimit,
    #[error("max blocking storage operations {value} exceeds supported limit {max}")]
    LimitTooLarge { value: usize, max: usize },
    #[error("blocking storage executor closed before drain completed")]
    Closed,
}

/// 하나의 연결 stream을 종료까지 처리한다. listener와 task 정책은 상위
/// Target 서비스의 책임이므로 TCP뿐 아니라 테스트용 duplex stream에도 쓸 수 있다.
pub async fn run_connection<S>(
    stream: S,
    connection: ConnectionStateMachine,
) -> Result<ConnectionCloseReason, ConnectionIoError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    run_connection_loop(stream, connection, BlockingStorageExecutor::default(), None).await
}

pub async fn run_connection_with_executor<S>(
    stream: S,
    connection: ConnectionStateMachine,
    storage_executor: BlockingStorageExecutor,
) -> Result<ConnectionCloseReason, ConnectionIoError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    run_connection_loop(stream, connection, storage_executor, None).await
}

pub(crate) async fn run_connection_with_executor_and_shutdown<S>(
    stream: S,
    connection: ConnectionStateMachine,
    storage_executor: BlockingStorageExecutor,
    shutdown: watch::Receiver<bool>,
) -> Result<ConnectionCloseReason, ConnectionIoError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    run_connection_loop(stream, connection, storage_executor, Some(shutdown)).await
}

async fn run_connection_loop<S>(
    mut stream: S,
    mut connection: ConnectionStateMachine,
    storage_executor: BlockingStorageExecutor,
    mut shutdown: Option<watch::Receiver<bool>>,
) -> Result<ConnectionCloseReason, ConnectionIoError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut codec = IscsiCodec::with_config(*connection.frame_config());
    let mut input = BytesMut::with_capacity(READ_CHUNK_LENGTH);
    let mut output = BytesMut::with_capacity(READ_CHUNK_LENGTH);
    let mut read_buffer = [0u8; READ_CHUNK_LENGTH];
    let mut shutdown_deadline = None;

    loop {
        if shutdown_deadline.is_none()
            && shutdown.as_ref().is_some_and(|receiver| *receiver.borrow())
        {
            shutdown_deadline =
                initiate_service_shutdown(&mut stream, &mut connection, &mut codec, &mut output)
                    .await?;
            if connection.phase() == ConnectionPhase::Closed {
                return connection
                    .close_reason()
                    .ok_or(ConnectionIoError::MissingCloseReason);
            }
        }
        if shutdown_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            connection.close(ConnectionCloseReason::ServiceShutdown);
            return connection
                .close_reason()
                .ok_or(ConnectionIoError::MissingCloseReason);
        }
        while let Some(frame) = codec.decode(&mut input)? {
            if !frame.ahs.is_empty() {
                connection.on_protocol_error();
                return Err(ConnectionIoError::UnexpectedAhs);
            }
            let response = if requires_blocking_storage(&frame.pdu) {
                let (returned, response) = storage_executor.receive(connection, frame.pdu).await?;
                connection = returned;
                response?
            } else {
                connection.receive(frame.pdu)?
            };
            let mut wrote_response = false;
            if let Some(pdu) = response.response {
                write_pdu(&mut stream, &mut codec, &mut output, pdu).await?;
                wrote_response = true;
            }
            for pdu in response.additional_responses {
                write_pdu(&mut stream, &mut codec, &mut output, pdu).await?;
                wrote_response = true;
            }
            if wrote_response {
                stream.flush().await?;
            }
            if response.transition_after_send {
                connection.response_sent()?;
                codec = IscsiCodec::with_config(*connection.frame_config());
            }
            if connection.phase() == ConnectionPhase::Closed {
                return connection
                    .close_reason()
                    .ok_or(ConnectionIoError::MissingCloseReason);
            }
        }

        let (duration, timeout_kind) = if let Some(deadline) = shutdown_deadline {
            (
                deadline.saturating_duration_since(Instant::now()),
                WaitTimeout::ServiceShutdown,
            )
        } else {
            match connection.phase() {
                ConnectionPhase::SecurityNegotiation
                | ConnectionPhase::LoginOperationalNegotiation => (
                    connection.timeouts().login,
                    WaitTimeout::Connection(ConnectionTimeoutKind::Login),
                ),
                ConnectionPhase::FullFeaturePhase => (
                    connection.timeouts().idle,
                    WaitTimeout::Connection(ConnectionTimeoutKind::Idle),
                ),
                ConnectionPhase::Logout => (
                    connection.timeouts().logout,
                    WaitTimeout::Connection(ConnectionTimeoutKind::Logout),
                ),
                ConnectionPhase::Closed => {
                    return connection
                        .close_reason()
                        .ok_or(ConnectionIoError::MissingCloseReason)
                }
            }
        };
        let input_limit = max_buffered_input_length(codec.frame_config());
        let Some(remaining) = input_limit.checked_sub(input.len()) else {
            connection.on_protocol_error();
            return Err(ConnectionIoError::InputBufferLimit { limit: input_limit });
        };
        if remaining == 0 {
            connection.on_protocol_error();
            return Err(ConnectionIoError::InputBufferLimit { limit: input_limit });
        }
        let read_length = remaining.min(read_buffer.len());
        let event = read_event(
            &mut stream,
            &mut read_buffer[..read_length],
            duration,
            if shutdown_deadline.is_none() {
                shutdown.as_mut()
            } else {
                None
            },
        )
        .await?;
        let read = match event {
            ReadEvent::Data(read) => read,
            ReadEvent::Shutdown => {
                shutdown_deadline = initiate_service_shutdown(
                    &mut stream,
                    &mut connection,
                    &mut codec,
                    &mut output,
                )
                .await?;
                if connection.phase() == ConnectionPhase::Closed {
                    return connection
                        .close_reason()
                        .ok_or(ConnectionIoError::MissingCloseReason);
                }
                continue;
            }
            ReadEvent::Timeout => match timeout_kind {
                WaitTimeout::ServiceShutdown => {
                    connection.close(ConnectionCloseReason::ServiceShutdown);
                    return connection
                        .close_reason()
                        .ok_or(ConnectionIoError::MissingCloseReason);
                }
                WaitTimeout::Connection(ConnectionTimeoutKind::Idle)
                    if !connection.has_pending_keepalive() =>
                {
                    let probe = connection.keepalive_probe(0)?;
                    write_pdu(&mut stream, &mut codec, &mut output, probe).await?;
                    stream.flush().await?;
                    continue;
                }
                WaitTimeout::Connection(timeout_kind) => {
                    connection.on_timeout(timeout_kind);
                    return connection
                        .close_reason()
                        .ok_or(ConnectionIoError::MissingCloseReason);
                }
            },
        };
        if read == 0 {
            connection.on_transport_error();
            return connection
                .close_reason()
                .ok_or(ConnectionIoError::MissingCloseReason);
        }
        input.extend_from_slice(&read_buffer[..read]);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitTimeout {
    Connection(ConnectionTimeoutKind),
    ServiceShutdown,
}

enum ReadEvent {
    Data(usize),
    Timeout,
    Shutdown,
}

async fn read_event<S>(
    stream: &mut S,
    buffer: &mut [u8],
    duration: std::time::Duration,
    mut shutdown: Option<&mut watch::Receiver<bool>>,
) -> Result<ReadEvent, std::io::Error>
where
    S: AsyncRead + Unpin,
{
    if let Some(receiver) = shutdown.as_mut() {
        loop {
            tokio::select! {
                changed = receiver.changed() => {
                    if changed.is_err() || *receiver.borrow() {
                        return Ok(ReadEvent::Shutdown);
                    }
                }
                result = timeout(duration, stream.read(buffer)) => {
                    return match result {
                        Ok(read) => read.map(ReadEvent::Data),
                        Err(_) => Ok(ReadEvent::Timeout),
                    };
                }
            }
        }
    }
    match timeout(duration, stream.read(buffer)).await {
        Ok(read) => read.map(ReadEvent::Data),
        Err(_) => Ok(ReadEvent::Timeout),
    }
}

async fn initiate_service_shutdown<S>(
    stream: &mut S,
    connection: &mut ConnectionStateMachine,
    codec: &mut IscsiCodec,
    output: &mut BytesMut,
) -> Result<Option<Instant>, ConnectionIoError>
where
    S: AsyncWrite + Unpin,
{
    if connection.phase() != ConnectionPhase::FullFeaturePhase {
        connection.close(ConnectionCloseReason::ServiceShutdown);
        return Ok(None);
    }
    let timeout = connection
        .timeouts()
        .logout
        .min(std::time::Duration::from_secs(u64::from(u16::MAX)));
    let timeout_seconds = timeout.as_secs() as u16;
    let request = connection.request_logout(timeout_seconds)?;
    write_pdu(stream, codec, output, request).await?;
    stream.flush().await?;
    Ok(Some(Instant::now() + timeout))
}

fn requires_blocking_storage(pdu: &Pdu) -> bool {
    matches!(pdu, Pdu::ScsiCommand(_) | Pdu::ScsiDataOut(_))
}

fn max_buffered_input_length(config: &FrameConfig) -> usize {
    BHS_LEN
        .saturating_add(config.max_ahs_length())
        .saturating_add(4)
        .saturating_add(config.max_recv_data_segment_length())
        .saturating_add(3)
        .saturating_add(4)
}

async fn write_pdu<S>(
    stream: &mut S,
    codec: &mut IscsiCodec,
    output: &mut BytesMut,
    pdu: Pdu,
) -> Result<(), ConnectionIoError>
where
    S: AsyncWrite + Unpin,
{
    codec.encode(pdu, output)?;
    stream.write_all(output).await?;
    output.clear();
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectionIoError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Codec(#[from] CodecError),
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    #[error("AHS is not accepted by the current Connection handler")]
    UnexpectedAhs,
    #[error("closed Connection has no close reason")]
    MissingCloseReason,
    #[error("connection input buffer reached the negotiated limit {limit}")]
    InputBufferLimit { limit: usize },
    #[error("blocking storage executor was closed")]
    StorageExecutorClosed,
    #[error("blocking storage task failed")]
    StorageTask(#[source] tokio::task::JoinError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::ConnectionStateMachine;
    use crate::control::{LogoutRequest, LogoutResponse, NopOut};
    use crate::login::{IscsiName, LoginRequest, LoginResponse, TextParameters};
    use crate::login_policy::TargetLoginPolicy;
    use crate::opcode::{LoginStage, TaskAttribute};
    use crate::scsi::ScsiCommand;
    use crate::scsi_target::{ScsiTarget, StorageBackend, StorageError};
    use crate::target_login::TargetLoginProcessor;
    use crate::Pdu;
    use tokio::net::{TcpListener, TcpStream};

    use std::sync::{Arc, Condvar, Mutex};
    use std::thread::ThreadId;
    use std::time::Duration;

    struct GatedBackend {
        started: Option<tokio::sync::oneshot::Sender<ThreadId>>,
        gate: Arc<(Mutex<bool>, Condvar)>,
    }

    impl StorageBackend for GatedBackend {
        fn block_size(&self) -> u32 {
            512
        }

        fn block_count(&self) -> u64 {
            1
        }

        fn read_only(&self) -> bool {
            false
        }

        fn read_blocks(&mut self, _lba: u64, output: &mut [u8]) -> Result<(), StorageError> {
            if let Some(started) = self.started.take() {
                let _ = started.send(std::thread::current().id());
            }
            let (lock, ready) = &*self.gate;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = ready.wait(released).unwrap();
            }
            output.fill(0x5a);
            Ok(())
        }

        fn write_blocks(&mut self, _lba: u64, _input: &[u8]) -> Result<(), StorageError> {
            Ok(())
        }

        fn flush(&mut self) -> Result<(), StorageError> {
            Ok(())
        }
    }

    async fn exchange(
        stream: &mut TcpStream,
        codec: &mut IscsiCodec,
        input: &mut BytesMut,
        pdu: Pdu,
    ) -> Pdu {
        let mut output = BytesMut::new();
        codec.encode(pdu, &mut output).unwrap();
        stream.write_all(&output).await.unwrap();
        loop {
            if let Some(frame) = codec.decode(input).unwrap() {
                return frame.pdu;
            }
            let read = stream.read_buf(input).await.unwrap();
            assert_ne!(read, 0);
        }
    }

    fn login_request(stage: LoginStage, next: LoginStage, text: &[u8], cmd_sn: u32) -> Pdu {
        Pdu::LoginRequest(LoginRequest {
            transit: true,
            continue_: false,
            current_stage: stage,
            next_stage: next,
            version_max: 0,
            version_min: 0,
            isid: [1, 2, 3, 4, 5, 6],
            tsih: 0,
            initiator_task_tag: 1,
            cid: 7,
            cmd_sn,
            exp_stat_sn: 0,
            params: TextParameters::parse(text),
        })
    }

    fn established_read_connection(
        backend: impl StorageBackend + 'static,
    ) -> (ConnectionStateMachine, Pdu) {
        let mut policy = TargetLoginPolicy::default();
        policy.set_target_name(IscsiName::parse("iqn.2024-01.com.example:target").unwrap());
        let mut connection =
            ConnectionStateMachine::new(TargetLoginProcessor::new(policy, 1), 7, 4).unwrap();
        connection
            .receive(login_request(
                LoginStage::Security,
                LoginStage::Operational,
                b"InitiatorName=iqn.2024-01.com.example:initiator\0TargetName=iqn.2024-01.com.example:target\0AuthMethod=None\0",
                10,
            ))
            .unwrap();
        connection.response_sent().unwrap();
        connection
            .receive(login_request(
                LoginStage::Operational,
                LoginStage::FullFeature,
                b"",
                11,
            ))
            .unwrap();
        connection.response_sent().unwrap();
        let exp_stat_sn = connection.sequence().unwrap().next_stat_sn();
        let mut target = ScsiTarget::default();
        target.add_lun(0, backend).unwrap();
        connection.set_scsi_target(target);
        let mut cdb = [0; 16];
        cdb[0] = 0x28;
        cdb[8] = 1;
        let command = Pdu::ScsiCommand(ScsiCommand {
            immediate: false,
            final_: true,
            read: true,
            write: false,
            attr: TaskAttribute::Simple,
            lun: 0,
            initiator_task_tag: 11,
            expected_data_transfer_length: 512,
            cmd_sn: 11,
            exp_stat_sn,
            cdb,
            immediate_data: bytes::Bytes::new(),
        });
        (connection, command)
    }

    fn release_gate(gate: &Arc<(Mutex<bool>, Condvar)>) {
        let (lock, ready) = &**gate;
        *lock.lock().unwrap() = true;
        ready.notify_all();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn storage_executor_offloads_and_bounds_blocking_operations() {
        let executor = BlockingStorageExecutor::new(1).unwrap();
        let first_gate = Arc::new((Mutex::new(false), Condvar::new()));
        let second_gate = Arc::new((Mutex::new(true), Condvar::new()));
        let (first_started_tx, first_started_rx) = tokio::sync::oneshot::channel();
        let (second_started_tx, second_started_rx) = tokio::sync::oneshot::channel();
        let (first_connection, first_command) = established_read_connection(GatedBackend {
            started: Some(first_started_tx),
            gate: first_gate.clone(),
        });
        let (second_connection, second_command) = established_read_connection(GatedBackend {
            started: Some(second_started_tx),
            gate: second_gate,
        });

        let caller_thread = std::thread::current().id();
        let first_executor = executor.clone();
        let first = tokio::spawn(async move {
            first_executor
                .receive(first_connection, first_command)
                .await
        });
        let blocking_thread = first_started_rx.await.unwrap();
        assert_ne!(blocking_thread, caller_thread);

        let second_executor = executor.clone();
        let second = tokio::spawn(async move {
            second_executor
                .receive(second_connection, second_command)
                .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), second_started_rx)
                .await
                .is_err()
        );

        release_gate(&first_gate);
        let (_, first_result) = first.await.unwrap().unwrap();
        first_result.unwrap();
        let (_, second_result) = second.await.unwrap().unwrap();
        second_result.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn storage_executor_drain_waits_for_started_blocking_operation() {
        let executor = BlockingStorageExecutor::new(1).unwrap();
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (connection, command) = established_read_connection(GatedBackend {
            started: Some(started_tx),
            gate: gate.clone(),
        });
        let operation_executor = executor.clone();
        let operation =
            tokio::spawn(async move { operation_executor.receive(connection, command).await });
        started_rx.await.unwrap();

        let drain_executor = executor.clone();
        let mut draining = tokio::spawn(async move { drain_executor.drain().await });
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut draining)
                .await
                .is_err()
        );

        release_gate(&gate);
        let (_, result) = operation.await.unwrap().unwrap();
        result.unwrap();
        draining.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn service_shutdown_waits_for_blocking_storage_before_closing_connection() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (mut connection, command) = established_read_connection(GatedBackend {
            started: Some(started_tx),
            gate: gate.clone(),
        });
        let mut timeouts = connection.timeouts();
        timeouts.logout = Duration::from_millis(50);
        connection.set_timeouts(timeouts);
        let executor = BlockingStorageExecutor::new(1).unwrap();
        let (mut client, server_stream) = tokio::io::duplex(4096);
        let (shutdown, receiver) = watch::channel(false);
        let mut server = tokio::spawn(run_connection_with_executor_and_shutdown(
            server_stream,
            connection,
            executor,
            receiver,
        ));

        let mut codec = IscsiCodec::new();
        let mut wire = BytesMut::new();
        codec.encode(command, &mut wire).unwrap();
        client.write_all(&wire).await.unwrap();
        started_rx.await.unwrap();
        shutdown.send(true).unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(50), &mut server)
            .await
            .is_err());

        release_gate(&gate);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), server)
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            ConnectionCloseReason::ServiceShutdown
        );
    }

    #[test]
    fn storage_executor_rejects_a_limit_that_cannot_be_drained() {
        let max_supported = Semaphore::MAX_PERMITS.min(u32::MAX as usize);
        let invalid = max_supported.saturating_add(1);
        assert!(matches!(
            BlockingStorageExecutor::new(invalid),
            Err(BlockingStorageExecutorError::LimitTooLarge { value, max })
                if value == invalid && max == max_supported
        ));
    }

    #[tokio::test]
    async fn real_tcp_connection_logs_in_and_logs_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut policy = TargetLoginPolicy::default();
            policy.set_target_name(IscsiName::parse("iqn.2024-01.com.example:target").unwrap());
            let connection =
                ConnectionStateMachine::new(TargetLoginProcessor::new(policy, 0x1234), 7, 4)
                    .unwrap();
            run_connection(stream, connection).await.unwrap()
        });

        let mut stream = TcpStream::connect(address).await.unwrap();
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
        assert!(matches!(
            security,
            Pdu::LoginResponse(LoginResponse {
                status_class: 0,
                ..
            })
        ));

        let operational = exchange(
            &mut stream,
            &mut codec,
            &mut input,
            login_request(LoginStage::Operational, LoginStage::FullFeature, b"", 11),
        )
        .await;
        assert!(matches!(
            operational,
            Pdu::LoginResponse(LoginResponse { transit: true, .. })
        ));

        let logout = exchange(
            &mut stream,
            &mut codec,
            &mut input,
            Pdu::LogoutRequest(LogoutRequest {
                immediate: true,
                reason_code: 0,
                initiator_task_tag: 9,
                cid: 7,
                cmd_sn: 11,
                exp_stat_sn: 2,
            }),
        )
        .await;
        assert!(matches!(
            logout,
            Pdu::LogoutResponse(LogoutResponse { response: 0, .. })
        ));
        assert_eq!(server.await.unwrap(), ConnectionCloseReason::NormalLogout);
    }

    #[tokio::test]
    async fn idle_connection_uses_nop_keepalive_before_timing_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut policy = TargetLoginPolicy::default();
            policy.set_target_name(IscsiName::parse("iqn.2024-01.com.example:target").unwrap());
            let mut connection =
                ConnectionStateMachine::new(TargetLoginProcessor::new(policy, 0x1234), 7, 4)
                    .unwrap();
            connection.set_timeouts(crate::connection::ConnectionTimeouts {
                login: Duration::from_secs(1),
                idle: Duration::from_millis(100),
                logout: Duration::from_secs(1),
            });
            run_connection(stream, connection).await.unwrap()
        });

        let mut stream = TcpStream::connect(address).await.unwrap();
        let mut codec = IscsiCodec::new();
        let mut input = BytesMut::new();
        exchange(
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
        exchange(
            &mut stream,
            &mut codec,
            &mut input,
            login_request(LoginStage::Operational, LoginStage::FullFeature, b"", 11),
        )
        .await;

        let probe = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Some(frame) = codec.decode(&mut input).unwrap() {
                    break frame.pdu;
                }
                let read = stream.read_buf(&mut input).await.unwrap();
                assert_ne!(read, 0);
            }
        })
        .await
        .unwrap();
        let Pdu::NopIn(probe) = probe else {
            panic!("expected target NOP-In probe");
        };
        assert_eq!(probe.initiator_task_tag, u32::MAX);
        assert_ne!(probe.target_transfer_tag, u32::MAX);

        let mut output = BytesMut::new();
        codec
            .encode(
                Pdu::NopOut(NopOut {
                    immediate: true,
                    lun: probe.lun,
                    initiator_task_tag: u32::MAX,
                    target_transfer_tag: probe.target_transfer_tag,
                    cmd_sn: probe.exp_cmd_sn,
                    exp_stat_sn: probe.stat_sn,
                    data: bytes::Bytes::new(),
                }),
                &mut output,
            )
            .unwrap();
        stream.write_all(&output).await.unwrap();

        let logout = exchange(
            &mut stream,
            &mut codec,
            &mut input,
            Pdu::LogoutRequest(LogoutRequest {
                immediate: true,
                reason_code: 0,
                initiator_task_tag: 9,
                cid: 7,
                cmd_sn: probe.exp_cmd_sn,
                exp_stat_sn: probe.stat_sn,
            }),
        )
        .await;
        assert!(matches!(
            logout,
            Pdu::LogoutResponse(LogoutResponse { response: 0, .. })
        ));
        assert_eq!(server.await.unwrap(), ConnectionCloseReason::NormalLogout);
    }
}
