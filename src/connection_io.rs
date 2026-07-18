//! 선택적 Tokio stream adapter for [`ConnectionStateMachine`].

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use tokio_util::codec::{Decoder, Encoder};

use crate::codec::IscsiCodec;
use crate::connection::{
    ConnectionCloseReason, ConnectionError, ConnectionPhase, ConnectionStateMachine,
    ConnectionTimeoutKind,
};
use crate::error::CodecError;

/// 하나의 연결 stream을 종료까지 처리한다. listener와 task 정책은 상위
/// Target 서비스의 책임이므로 TCP뿐 아니라 테스트용 duplex stream에도 쓸 수 있다.
pub async fn run_connection<S>(
    mut stream: S,
    mut connection: ConnectionStateMachine,
) -> Result<ConnectionCloseReason, ConnectionIoError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut codec = IscsiCodec::with_config(*connection.frame_config());
    let mut input = BytesMut::with_capacity(8192);
    let mut output = BytesMut::with_capacity(8192);

    loop {
        while let Some(frame) = codec.decode(&mut input)? {
            if !frame.ahs.is_empty() {
                connection.on_protocol_error();
                return Err(ConnectionIoError::UnexpectedAhs);
            }
            let response = connection.receive(frame.pdu)?;
            if let Some(pdu) = response.response {
                codec.encode(pdu, &mut output)?;
                stream.write_all(&output).await?;
                stream.flush().await?;
                output.clear();
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

        let (duration, timeout_kind) = match connection.phase() {
            ConnectionPhase::SecurityNegotiation | ConnectionPhase::LoginOperationalNegotiation => {
                (connection.timeouts().login, ConnectionTimeoutKind::Login)
            }
            ConnectionPhase::FullFeaturePhase => {
                (connection.timeouts().idle, ConnectionTimeoutKind::Idle)
            }
            ConnectionPhase::Logout => {
                (connection.timeouts().logout, ConnectionTimeoutKind::Logout)
            }
            ConnectionPhase::Closed => {
                return connection
                    .close_reason()
                    .ok_or(ConnectionIoError::MissingCloseReason)
            }
        };
        let read = match timeout(duration, stream.read_buf(&mut input)).await {
            Ok(result) => result?,
            Err(_) => {
                if timeout_kind == ConnectionTimeoutKind::Idle
                    && !connection.has_pending_keepalive()
                {
                    let probe = connection.keepalive_probe(0)?;
                    codec.encode(probe, &mut output)?;
                    stream.write_all(&output).await?;
                    stream.flush().await?;
                    output.clear();
                    continue;
                }
                connection.on_timeout(timeout_kind);
                return connection
                    .close_reason()
                    .ok_or(ConnectionIoError::MissingCloseReason);
            }
        };
        if read == 0 {
            connection.on_transport_error();
            return connection
                .close_reason()
                .ok_or(ConnectionIoError::MissingCloseReason);
        }
    }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::ConnectionStateMachine;
    use crate::control::{LogoutRequest, LogoutResponse, NopOut};
    use crate::login::{IscsiName, LoginRequest, LoginResponse, TextParameters};
    use crate::login_policy::TargetLoginPolicy;
    use crate::opcode::LoginStage;
    use crate::target_login::TargetLoginProcessor;
    use crate::Pdu;
    use tokio::net::{TcpListener, TcpStream};

    use std::time::Duration;

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
