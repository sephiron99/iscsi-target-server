#![cfg(feature = "daemon")]
//! daemon CLI 통합 테스트: 실제 `iscsi-targetd` binary를 실행해 설정 검증,
//! login/logout을 확인한다.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use pdu::control::LogoutRequest;
use pdu::login::{LoginRequest, LoginResponse, TextParameters};
use pdu::opcode::LoginStage;
use pdu::{Pdu, BHS_LEN};

const TARGET_NAME: &str = "iqn.2026-07.example.com:cli";

fn binary() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_iscsi-targetd"))
}

static TEST_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let counter = TEST_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "iscsi-targetd-cli-{label}-{}-{counter}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn write_config(directory: &TestDirectory, port: u16) -> PathBuf {
    let path = directory.path("daemon.toml");
    std::fs::write(
        &path,
        format!(
            r#"version = 1

[listen]
address = "127.0.0.1"
port = {port}

[[targets]]
name = "{TARGET_NAME}"

[[targets.luns]]
lun = 0
backend = "memory"
block-size = 512
block-count = 64
"#
        ),
    )
    .unwrap();
    path
}

#[test]
fn help_prints_usage_on_stdout() {
    let output = Command::new(binary()).arg("--help").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--config"));
    assert!(stdout.contains("--check"));
}

#[test]
fn missing_config_argument_fails_with_usage() {
    let output = Command::new(binary()).output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--config"));
}

#[test]
fn check_validates_configuration_without_serving() {
    let directory = TestDirectory::new("check");
    let config = write_config(&directory, free_port());
    let output = Command::new(binary())
        .args(["--config", config.to_str().unwrap(), "--check"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("설정 검증 성공"));
}

#[test]
fn invalid_configuration_fails_without_leaking_inline_secret() {
    let directory = TestDirectory::new("invalid");
    let config = write_config(&directory, free_port());
    let mut contents = std::fs::read_to_string(&config).unwrap();
    contents.push_str(
        "\n[targets.authentication]\nmethod = \"chap\"\nusername = \"user\"\nsecret-file = \"chap.secret\"\nsecret = \"top-secret-value\"\n",
    );
    std::fs::write(&config, contents).unwrap();

    let output = Command::new(binary())
        .args(["--config", config.to_str().unwrap(), "--check"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stdout.contains("top-secret-value"));
    assert!(!stderr.contains("top-secret-value"));
}

const INITIATOR_NAME: &str = "iqn.2026-07.example.com:initiator";

/// 테스트가 끝나거나 실패해도 daemon process가 남지 않도록 drop 시 강제 종료한다.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn send_pdu(stream: &mut TcpStream, pdu: Pdu) {
    stream.write_all(&pdu.encode()).unwrap();
}

fn receive_pdu(stream: &mut TcpStream) -> Pdu {
    let mut bhs = [0u8; BHS_LEN];
    stream.read_exact(&mut bhs).unwrap();
    let data_length = ((bhs[5] as usize) << 16) | ((bhs[6] as usize) << 8) | (bhs[7] as usize);
    let padded_length = (data_length + 3) & !3;
    let mut data = vec![0u8; padded_length];
    stream.read_exact(&mut data).unwrap();
    Pdu::decode(&bhs, Bytes::copy_from_slice(&data[..data_length])).unwrap()
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

fn login_response(pdu: Pdu) -> LoginResponse {
    let Pdu::LoginResponse(response) = pdu else {
        panic!("expected LoginResponse, got {pdu:?}");
    };
    assert_eq!(response.status_class, 0, "login rejected: {response:?}");
    response
}

#[test]
fn daemon_serves_login_and_logout() {
    let directory = TestDirectory::new("serve");
    let config = write_config(&directory, free_port());
    let mut child = ChildGuard(
        Command::new(binary())
            .args(["--config", config.to_str().unwrap()])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let stdout = child.0.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    let address: SocketAddr = loop {
        let line = lines
            .next()
            .expect("daemon stdout closed before listening line")
            .unwrap();
        if let Some(rest) = line.strip_prefix("listening ") {
            break rest.parse().unwrap();
        }
    };

    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    send_pdu(
        &mut stream,
        login_request(
            LoginStage::Security,
            LoginStage::Operational,
            format!("InitiatorName={INITIATOR_NAME}\0TargetName={TARGET_NAME}\0AuthMethod=None\0")
                .as_bytes(),
            10,
        ),
    );
    let security = login_response(receive_pdu(&mut stream));
    assert!(security.transit);

    send_pdu(
        &mut stream,
        login_request(LoginStage::Operational, LoginStage::FullFeature, b"", 11),
    );
    let operational = login_response(receive_pdu(&mut stream));
    assert!(operational.transit);

    send_pdu(
        &mut stream,
        Pdu::LogoutRequest(LogoutRequest {
            immediate: true,
            reason_code: 0,
            initiator_task_tag: 9,
            cid: 0x1234,
            cmd_sn: 11,
            exp_stat_sn: operational.stat_sn.wrapping_add(1),
        }),
    );
    let logout = receive_pdu(&mut stream);
    assert!(
        matches!(logout, Pdu::LogoutResponse(ref response) if response.response == 0),
        "unexpected logout response: {logout:?}"
    );
}
