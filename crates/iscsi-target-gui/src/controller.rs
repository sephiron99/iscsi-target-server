//! UI thread와 분리된 서버 제어.
//!
//! [`Controller`]는 자기 thread에 Tokio runtime을 만들고 그 안에서 서버를 띄운다.
//! UI thread는 [`Controller::start`], [`Controller::stop`]으로 명령을 보내고
//! [`Controller::try_event`]로 결과를 가져간다. 두 방향 모두 channel이라 UI thread는
//! 서버 작업을 기다리며 멈추지 않는다.
//!
//! 종료 순서: [`Controller::shutdown`]이 명령 channel을 닫는다 → worker가 실행 중인
//! 서버에 종료를 요청하고 끝나기를 기다린다 → runtime을 내린다 → `shutdown`이 worker
//! thread를 join한다. storage backend는 이 과정에서 닫히므로, 서버가 offline으로
//! 바꿔 둔 physical disk도 여기서 online으로 돌아간다.

use std::cell::{Cell, RefCell};
use std::net::SocketAddr;
use std::sync::mpsc as std_mpsc;
use std::thread::JoinHandle;

use iscsi_target_server::server::{Server, ServerError};
use iscsi_target_server::{
    AuthenticationPolicy, LunBackendConfig, ServerConfig, TargetServiceError, TargetServiceSummary,
};
use tokio::sync::{mpsc, oneshot};

/// UI가 보여 주는 서버 상태.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ServerState {
    #[default]
    Stopped,
    Starting,
    Running,
    Stopping,
}

impl ServerState {
    /// event를 받은 뒤의 상태.
    pub fn after(self, event: &Event) -> Self {
        match event {
            Event::Starting => Self::Starting,
            Event::Started { .. } => Self::Running,
            Event::Stopping => Self::Stopping,
            Event::StartFailed(_) | Event::Stopped(_) | Event::Failed(_) => Self::Stopped,
        }
    }

    pub fn can_start(self) -> bool {
        self == Self::Stopped
    }

    pub fn can_stop(self) -> bool {
        self == Self::Running
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Stopped => "Stopped",
            Self::Starting => "Starting...",
            Self::Running => "Running",
            Self::Stopping => "Stopping...",
        }
    }
}

/// worker가 UI에 알리는 일. 오류는 UI가 그대로 보여 줄 수 있는 문구로 온다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Starting,
    Started {
        address: SocketAddr,
        targets: Vec<TargetView>,
    },
    /// 설정을 읽지 못했거나 listen하지 못했다. 서버는 뜨지 않았다.
    StartFailed(String),
    Stopping,
    Stopped(TargetServiceSummary),
    /// 실행 중이던 서버가 오류로 끝났다.
    Failed(String),
}

/// 실행 중인 Target 하나를 화면에 보여 주기 위한 값.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetView {
    pub name: String,
    pub authentication: &'static str,
    pub luns: Vec<LunView>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LunView {
    pub lun: u64,
    pub backend: String,
    pub block_size: u32,
    pub block_count: u64,
    pub read_only: bool,
}

impl LunView {
    /// byte 단위 용량. 곱이 넘치면 `None`이다.
    pub fn capacity_bytes(&self) -> Option<u64> {
        u64::from(self.block_size).checked_mul(self.block_count)
    }
}

enum Command {
    Start { config: Box<ServerConfig> },
    Stop,
}

/// 서버를 돌리는 worker thread의 손잡이. UI thread 하나에서만 쓴다.
pub struct Controller {
    commands: RefCell<Option<mpsc::UnboundedSender<Command>>>,
    events: std_mpsc::Receiver<Event>,
    worker: Cell<Option<JoinHandle<()>>>,
}

impl Controller {
    /// Tokio runtime과 worker thread를 만든다. 서버는 아직 띄우지 않는다.
    pub fn spawn() -> std::io::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let (command_sender, command_receiver) = mpsc::unbounded_channel();
        let (event_sender, event_receiver) = std_mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("target-controller".to_owned())
            .spawn(move || runtime.block_on(run(command_receiver, event_sender)))?;
        Ok(Self {
            commands: RefCell::new(Some(command_sender)),
            events: event_receiver,
            worker: Cell::new(Some(worker)),
        })
    }

    /// 이 설정으로 서버를 띄우라고 요청한다. 이미 떠 있으면 무시된다.
    pub fn start(&self, config: ServerConfig) {
        self.send(Command::Start {
            config: Box::new(config),
        });
    }

    /// 서버를 내리라고 요청한다. 떠 있지 않으면 무시된다.
    pub fn stop(&self) {
        self.send(Command::Stop);
    }

    /// 쌓인 event를 하나 꺼낸다. 기다리지 않는다.
    pub fn try_event(&self) -> Option<Event> {
        self.events.try_recv().ok()
    }

    /// 서버를 내리고 worker thread가 끝날 때까지 기다린다. 여러 번 불러도 된다.
    pub fn shutdown(&self) {
        // sender를 버리면 worker의 명령 loop가 끝난다.
        self.commands.borrow_mut().take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }

    fn send(&self, command: Command) {
        if let Some(sender) = self.commands.borrow().as_ref() {
            // worker가 이미 끝났으면 받을 곳이 없다. 그때는 보낼 일도 없다.
            let _ = sender.send(command);
        }
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.shutdown();
    }
}

type ServerResult = Result<TargetServiceSummary, ServerError>;

struct Running {
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<ServerResult>,
}

impl Running {
    /// 처음 요청했을 때만 `true`를 돌려준다.
    fn request_stop(&mut self) -> bool {
        match self.stop.take() {
            Some(stop) => {
                let _ = stop.send(());
                true
            }
            None => false,
        }
    }
}

async fn run(mut commands: mpsc::UnboundedReceiver<Command>, events: std_mpsc::Sender<Event>) {
    // UI가 사라져 받을 곳이 없어도 서버 정리는 끝까지 해야 하므로 전송 실패는 무시한다.
    let emit = |event: Event| {
        let _ = events.send(event);
    };
    let mut running: Option<Running> = None;
    loop {
        tokio::select! {
            command = commands.recv() => match command {
                Some(Command::Start { config }) => {
                    if running.is_some() {
                        continue;
                    }
                    emit(Event::Starting);
                    match start(&config).await {
                        Ok((started, address, targets)) => {
                            running = Some(started);
                            emit(Event::Started { address, targets });
                        }
                        Err(message) => emit(Event::StartFailed(message)),
                    }
                }
                Some(Command::Stop) => {
                    if running.as_mut().is_some_and(Running::request_stop) {
                        emit(Event::Stopping);
                    }
                }
                None => break,
            },
            result = finished(&mut running) => {
                running = None;
                emit(outcome(result));
            }
        }
    }
    if let Some(mut last) = running {
        if last.request_stop() {
            emit(Event::Stopping);
        }
        emit(outcome(last.task.await));
    }
}

/// 실행 중인 서버가 끝나기를 기다린다. 서버가 없으면 끝나지 않는다.
async fn finished(running: &mut Option<Running>) -> Result<ServerResult, tokio::task::JoinError> {
    match running {
        Some(running) => (&mut running.task).await,
        None => std::future::pending().await,
    }
}

fn outcome(result: Result<ServerResult, tokio::task::JoinError>) -> Event {
    match result {
        Ok(Ok(summary)) => Event::Stopped(summary),
        Ok(Err(error)) => Event::Failed(error.to_string()),
        Err(error) => Event::Failed(format!("the server task ended abnormally: {error}")),
    }
}

async fn start(config: &ServerConfig) -> Result<(Running, SocketAddr, Vec<TargetView>), String> {
    let server = Server::bind(config)
        .await
        .map_err(|error| error.to_string())?;
    let address = server
        .local_addr()
        .map_err(TargetServiceError::from)
        .map_err(|error| error.to_string())?;
    let targets = target_views(config, &server)?;

    let (stop_sender, stop_receiver) = oneshot::channel::<()>();
    let task = tokio::spawn(server.run(async move {
        // sender가 버려져도 종료 요청으로 본다.
        let _ = stop_receiver.await;
    }));
    Ok((
        Running {
            stop: Some(stop_sender),
            task,
        },
        address,
        targets,
    ))
}

/// 설정의 backend 종류와, 실제로 연 backend가 알려 준 크기를 합친다.
fn target_views(config: &ServerConfig, server: &Server) -> Result<Vec<TargetView>, String> {
    let statuses = server.api().targets().map_err(|error| error.to_string())?;
    Ok(statuses
        .into_iter()
        .map(|status| {
            let configured = config
                .targets()
                .iter()
                .find(|target| target.name() == &status.name);
            let luns = status
                .luns
                .iter()
                .map(|info| {
                    let backend = configured
                        .and_then(|target| target.luns().iter().find(|lun| lun.lun() == info.lun))
                        .map(|lun| describe_backend(lun.backend()))
                        .unwrap_or_default();
                    LunView {
                        lun: info.lun,
                        backend,
                        block_size: info.block_size,
                        block_count: info.block_count,
                        read_only: info.read_only,
                    }
                })
                .collect();
            TargetView {
                name: status.name.as_str().to_owned(),
                authentication: describe_authentication(status.authentication),
                luns,
            }
        })
        .collect())
}

fn describe_authentication(policy: AuthenticationPolicy) -> &'static str {
    match policy {
        AuthenticationPolicy::NoneOnly => "no authentication",
        AuthenticationPolicy::ChapOnly => "CHAP required",
        AuthenticationPolicy::PreferChap => "CHAP preferred",
    }
}

pub fn describe_backend(backend: &LunBackendConfig) -> String {
    match backend {
        LunBackendConfig::Memory { .. } => "Memory".to_owned(),
        LunBackendConfig::File { path, .. } => format!("File {}", path.display()),
        LunBackendConfig::WindowsPhysicalDrive { device_number, .. } => {
            format!("Physical drive {device_number}")
        }
        LunBackendConfig::WindowsVolume { drive_letter, .. } => {
            format!("Volume {}:", drive_letter.to_ascii_uppercase())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iscsi_target_server::{IscsiName, ListenConfig, LunConfig, TargetConfig};
    use std::time::{Duration, Instant};

    const TARGET_NAME: &str = "iqn.2026-10.example.com:gui";

    fn config(port: u16) -> ServerConfig {
        let name = IscsiName::parse(TARGET_NAME).unwrap();
        let mut target = TargetConfig::new(name);
        target
            .add_lun(
                LunConfig::new(
                    3,
                    LunBackendConfig::Memory {
                        block_size: 512,
                        block_count: 64,
                        read_only: true,
                    },
                )
                .unwrap(),
            )
            .unwrap();
        let listen = ListenConfig::new("127.0.0.1".parse().unwrap(), port).unwrap();
        let mut config = ServerConfig::new(listen, 4).unwrap();
        config.add_target(target).unwrap();
        config
    }

    /// port를 여는 테스트를 한 번에 하나씩만 돌린다.
    ///
    /// `free_port`는 빈 port를 골라 닫은 뒤 번호만 돌려주므로, 서버가 그 port를 열기
    /// 전에 나란히 도는 다른 테스트가 같은 port를 가져갈 수 있다.
    fn exclusive_ports() -> std::sync::MutexGuard<'static, ()> {
        static PORTS: std::sync::Mutex<()> = std::sync::Mutex::new(());
        PORTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn next_event(controller: &Controller) -> Event {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(event) = controller.try_event() {
                return event;
            }
            assert!(Instant::now() < deadline, "no event from the controller");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn start_reports_the_listening_target_and_stop_reports_the_summary() {
        let _ports = exclusive_ports();
        let port = free_port();
        let controller = Controller::spawn().unwrap();

        controller.start(config(port));
        assert_eq!(next_event(&controller), Event::Starting);
        let Event::Started { address, targets } = next_event(&controller) else {
            panic!("expected Started");
        };
        assert_eq!(address, SocketAddr::from(([127, 0, 0, 1], port)));
        assert_eq!(
            targets,
            vec![TargetView {
                name: TARGET_NAME.to_owned(),
                authentication: "no authentication",
                luns: vec![LunView {
                    lun: 3,
                    backend: "Memory".to_owned(),
                    block_size: 512,
                    block_count: 64,
                    read_only: true,
                }],
            }]
        );
        // 실제로 listen하고 있다.
        std::net::TcpStream::connect(address).unwrap();

        controller.stop();
        assert_eq!(next_event(&controller), Event::Stopping);
        assert!(matches!(next_event(&controller), Event::Stopped(_)));

        // 내린 뒤에는 같은 port로 다시 띄울 수 있다.
        controller.start(config(port));
        assert_eq!(next_event(&controller), Event::Starting);
        assert!(matches!(next_event(&controller), Event::Started { .. }));
    }

    #[test]
    fn invalid_configuration_fails_the_start_and_leaves_the_controller_usable() {
        let _ports = exclusive_ports();
        let controller = Controller::spawn().unwrap();

        // Target이 없는 설정은 listen하기 전에 거절된다.
        controller.start(ServerConfig::default());
        assert_eq!(next_event(&controller), Event::Starting);
        assert_eq!(
            next_event(&controller),
            Event::StartFailed("configuration must contain at least one Target".to_owned())
        );

        controller.start(config(free_port()));
        assert_eq!(next_event(&controller), Event::Starting);
        assert!(matches!(next_event(&controller), Event::Started { .. }));
    }

    #[test]
    fn port_already_in_use_fails_the_start() {
        let _ports = exclusive_ports();
        let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let controller = Controller::spawn().unwrap();

        controller.start(config(occupied.local_addr().unwrap().port()));
        assert_eq!(next_event(&controller), Event::Starting);
        assert!(matches!(next_event(&controller), Event::StartFailed(_)));
    }

    #[test]
    fn start_while_running_and_stop_while_stopped_are_ignored() {
        let _ports = exclusive_ports();
        let server_config = config(free_port());
        let controller = Controller::spawn().unwrap();

        controller.stop();
        controller.start(server_config.clone());
        assert_eq!(next_event(&controller), Event::Starting);
        assert!(matches!(next_event(&controller), Event::Started { .. }));

        controller.start(server_config);
        controller.stop();
        controller.stop();
        assert_eq!(next_event(&controller), Event::Stopping);
        assert!(matches!(next_event(&controller), Event::Stopped(_)));
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(controller.try_event(), None);
    }

    #[test]
    fn shutdown_stops_a_running_server_and_releases_the_port() {
        let _ports = exclusive_ports();
        let port = free_port();
        let controller = Controller::spawn().unwrap();

        controller.start(config(port));
        assert_eq!(next_event(&controller), Event::Starting);
        assert!(matches!(next_event(&controller), Event::Started { .. }));

        controller.shutdown();
        assert_eq!(controller.try_event(), Some(Event::Stopping));
        assert!(matches!(controller.try_event(), Some(Event::Stopped(_))));
        std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();

        // 내린 뒤의 명령과 두 번째 shutdown은 아무 일도 하지 않는다.
        controller.start(config(port));
        controller.shutdown();
        assert_eq!(controller.try_event(), None);
    }

    #[test]
    fn state_follows_events_and_gates_the_buttons() {
        let started = Event::Started {
            address: SocketAddr::from(([127, 0, 0, 1], 3260)),
            targets: Vec::new(),
        };
        let mut state = ServerState::default();
        assert!(state.can_start() && !state.can_stop());

        state = state.after(&Event::Starting);
        assert_eq!(state, ServerState::Starting);
        assert!(!state.can_start() && !state.can_stop());

        state = state.after(&started);
        assert_eq!(state, ServerState::Running);
        assert!(!state.can_start() && state.can_stop());

        state = state.after(&Event::Stopping);
        assert_eq!(state, ServerState::Stopping);
        assert!(!state.can_start() && !state.can_stop());

        state = state.after(&Event::Stopped(TargetServiceSummary::default()));
        assert_eq!(state, ServerState::Stopped);

        assert_eq!(
            ServerState::Starting.after(&Event::StartFailed(String::new())),
            ServerState::Stopped
        );
        assert_eq!(
            ServerState::Running.after(&Event::Failed(String::new())),
            ServerState::Stopped
        );
    }

    #[test]
    fn lun_capacity_is_checked() {
        let mut lun = LunView {
            lun: 0,
            backend: String::new(),
            block_size: 4096,
            block_count: 256,
            read_only: false,
        };
        assert_eq!(lun.capacity_bytes(), Some(1024 * 1024));
        lun.block_count = u64::MAX;
        assert_eq!(lun.capacity_bytes(), None);
    }
}
