//! Target와 LUN의 runtime 상태를 변경하고 조회하는 관리 service API.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::auth::ChapError;
use crate::config::{AuthenticationConfig, ConfigError, LunBackendConfig, LunConfig, TargetConfig};
use crate::connection::{ConnectionError, ConnectionStateMachine};
use crate::control_state::DiscoveryTarget;
use crate::login::IscsiName;
use crate::login_policy::AuthenticationPolicy;
use crate::scsi_target::{
    FileBackend, LunInfo, MemoryBackend, ScsiTarget, SharedScsiTarget, SharedScsiTargetError,
    StorageBackend, StorageError,
};
use crate::target_login::TargetLoginProcessor;

#[derive(Debug, Clone)]
pub struct TargetServiceApi {
    inner: Arc<RwLock<HashMap<IscsiName, ManagedTarget>>>,
}

#[derive(Debug)]
struct ManagedTarget {
    config: TargetConfig,
    scsi: SharedScsiTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetStatus {
    pub name: IscsiName,
    pub authentication: AuthenticationPolicy,
    pub luns: Vec<LunInfo>,
}

impl TargetServiceApi {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// File/device open을 포함할 수 있으므로 async caller는 blocking worker에서 호출해야 한다.
    pub fn add_target(&self, config: TargetConfig) -> Result<(), ManagementError> {
        {
            let targets = self.read()?;
            if targets.contains_key(config.name()) {
                return Err(ManagementError::DuplicateTarget(config.name().clone()));
            }
        }

        let mut target = ScsiTarget::default();
        // 장치 식별자가 Target마다 달라지도록 iSCSI name을 namespace로 쓴다.
        target.set_identity_namespace(config.name().as_str());
        let mut opened = Vec::with_capacity(config.luns().len());
        for lun in config.luns() {
            let (backend, facts) = open_backend(lun)?;
            target
                .add_boxed_lun(lun.lun(), backend)
                .map_err(SharedScsiTargetError::from)?;
            opened.push((lun, facts));
        }
        // 모든 backend가 열린 뒤에 한꺼번에 남긴다. 중간에 실패한 기동이 일부 LUN만
        // 준비된 것처럼 보이지 않게 한다.
        log_target_ready(&config);
        let info = target.lun_info();
        for (lun, facts) in &opened {
            if let Some(info) = info.iter().find(|info| info.lun == lun.lun()) {
                log_lun_ready(lun, info, &target.lun_serial_number(lun.lun()), facts);
            }
        }
        let managed = ManagedTarget {
            config,
            scsi: target.into(),
        };
        let mut targets = self.write()?;
        if targets.contains_key(managed.config.name()) {
            return Err(ManagementError::DuplicateTarget(
                managed.config.name().clone(),
            ));
        }
        targets.insert(managed.config.name().clone(), managed);
        Ok(())
    }

    pub fn remove_target(&self, name: &IscsiName) -> Result<bool, ManagementError> {
        Ok(self.write()?.remove(name).is_some())
    }

    /// File/device open을 포함할 수 있으므로 async caller는 blocking worker에서 호출해야 한다.
    pub fn add_lun(&self, target_name: &IscsiName, lun: LunConfig) -> Result<(), ManagementError> {
        {
            let targets = self.read()?;
            let target = targets
                .get(target_name)
                .ok_or_else(|| ManagementError::TargetNotFound(target_name.clone()))?;
            if target
                .config
                .luns()
                .iter()
                .any(|existing| existing.lun() == lun.lun())
            {
                return Err(ManagementError::DuplicateLun(lun.lun()));
            }
        }

        let (backend, facts) = open_backend(&lun)?;
        let info = LunInfo {
            lun: lun.lun(),
            block_size: backend.block_size(),
            block_count: backend.block_count(),
            read_only: backend.read_only(),
        };
        let mut targets = self.write()?;
        let target = targets
            .get_mut(target_name)
            .ok_or_else(|| ManagementError::TargetNotFound(target_name.clone()))?;
        if target
            .config
            .luns()
            .iter()
            .any(|existing| existing.lun() == lun.lun())
        {
            return Err(ManagementError::DuplicateLun(lun.lun()));
        }
        target.scsi.add_boxed_lun(lun.lun(), backend)?;
        if let Err(error) = target.config.add_lun(lun.clone()) {
            let _ = target.scsi.remove_lun(lun.lun());
            return Err(error.into());
        }
        log_lun_ready(
            &lun,
            &info,
            &target.scsi.lun_serial_number(lun.lun())?,
            &facts,
        );
        Ok(())
    }

    pub fn remove_lun(&self, target_name: &IscsiName, lun: u64) -> Result<bool, ManagementError> {
        let mut targets = self.write()?;
        let target = targets
            .get_mut(target_name)
            .ok_or_else(|| ManagementError::TargetNotFound(target_name.clone()))?;
        if !target.scsi.remove_lun(lun)? {
            return Ok(false);
        }
        target.config.remove_lun(lun);
        Ok(true)
    }

    pub fn targets(&self) -> Result<Vec<TargetStatus>, ManagementError> {
        let targets = self.read()?;
        let mut status = targets
            .values()
            .map(target_status)
            .collect::<Result<Vec<_>, _>>()?;
        status.sort_by(|left, right| left.name.as_str().cmp(right.name.as_str()));
        Ok(status)
    }

    pub fn target(&self, name: &IscsiName) -> Result<Option<TargetStatus>, ManagementError> {
        self.read()?.get(name).map(target_status).transpose()
    }

    pub fn create_connection(
        &self,
        target_name: &IscsiName,
        tsih: u16,
        command_window: u32,
    ) -> Result<ConnectionStateMachine, ManagementError> {
        let targets = self.read()?;
        let target = targets
            .get(target_name)
            .ok_or_else(|| ManagementError::TargetNotFound(target_name.clone()))?;
        let policy = target.config.login_policy();
        let processor = match target.config.authentication() {
            AuthenticationConfig::None => TargetLoginProcessor::new(policy, tsih),
            AuthenticationConfig::Chap(config) | AuthenticationConfig::PreferChap(config) => {
                TargetLoginProcessor::with_chap_credentials(policy, tsih, config.credentials()?)
            }
        };
        let scsi = target.scsi.clone();
        let discovery_targets = targets.keys().cloned().map(DiscoveryTarget::new).collect();
        drop(targets);

        let mut connection = ConnectionStateMachine::new_unbound(processor, command_window)?;
        connection.set_shared_scsi_target(scsi);
        connection.set_discovery_targets(discovery_targets);
        Ok(connection)
    }

    fn read(
        &self,
    ) -> Result<std::sync::RwLockReadGuard<'_, HashMap<IscsiName, ManagedTarget>>, ManagementError>
    {
        self.inner
            .read()
            .map_err(|_| ManagementError::RegistryPoisoned)
    }

    fn write(
        &self,
    ) -> Result<std::sync::RwLockWriteGuard<'_, HashMap<IscsiName, ManagedTarget>>, ManagementError>
    {
        self.inner
            .write()
            .map_err(|_| ManagementError::RegistryPoisoned)
    }
}

impl Default for TargetServiceApi {
    fn default() -> Self {
        Self::new()
    }
}

fn target_status(target: &ManagedTarget) -> Result<TargetStatus, ManagementError> {
    Ok(TargetStatus {
        name: target.config.name().clone(),
        authentication: target.config.authentication().policy(),
        luns: target.scsi.lun_info()?,
    })
}

/// backend를 여는 동안에만 알 수 있는 사실. 기동 로그에 쓴다.
#[derive(Debug, Default)]
struct BackendFacts {
    /// physical disk의 장치 정보. 물을 수 없었으면 `None`이다.
    disk: Option<DiskFacts>,
    /// 식별자 가상화가 실제로 바꿔 보여 주는 값이 있는지. 가상화를 켰을 때만 있다.
    virtual_identity_active: Option<bool>,
    /// physical disk를 host로부터 보호하는 방식.
    disk_protection: Option<String>,
}

#[derive(Debug)]
struct DiskFacts {
    model: String,
    bus: String,
    removable: bool,
    serial_number: String,
}

/// backend를 열고, 실패하면 어느 LUN의 어떤 backend였는지를 오류에 붙인다.
fn open_backend(
    lun: &LunConfig,
) -> Result<(Box<dyn StorageBackend>, BackendFacts), ManagementError> {
    build_backend(lun.backend()).map_err(|source| ManagementError::LunBackend {
        lun: lun.lun(),
        backend: lun.backend().to_string(),
        source: Box::new(source),
    })
}

/// 기동할 때 Target 하나의 요약을 남긴다. CHAP secret과 그 파일 경로는 남기지 않는다.
fn log_target_ready(config: &TargetConfig) {
    let name = config.name().as_str();
    let luns = config.luns().len();
    match config.authentication() {
        AuthenticationConfig::None => {
            tracing::info!(name, authentication = "none", luns, "Target ready");
        }
        AuthenticationConfig::Chap(chap) => tracing::info!(
            name,
            authentication = "chap",
            chap_user = chap.username(),
            luns,
            "Target ready"
        ),
        AuthenticationConfig::PreferChap(chap) => tracing::info!(
            name,
            authentication = "prefer-chap",
            chap_user = chap.username(),
            luns,
            "Target ready"
        ),
    }
}

/// 열린 LUN 하나를 남긴다. 크기는 설정이 아니라 연 backend가 알려 준 값이다.
fn log_lun_ready(config: &LunConfig, info: &LunInfo, serial: &str, facts: &BackendFacts) {
    let lun = info.lun;
    let capacity_bytes = u64::from(info.block_size).saturating_mul(info.block_count);
    let (block_size, block_count, read_only) = (info.block_size, info.block_count, info.read_only);
    match config.backend() {
        LunBackendConfig::Memory { .. } => tracing::info!(
            lun,
            backend = "memory",
            capacity_bytes,
            block_size,
            block_count,
            read_only,
            serial,
            "LUN ready"
        ),
        LunBackendConfig::File {
            path,
            durable_flush,
            ..
        } => tracing::info!(
            lun,
            backend = "file",
            path = %path.display(),
            capacity_bytes,
            block_size,
            block_count,
            read_only,
            durable_flush,
            serial,
            "LUN ready"
        ),
        LunBackendConfig::WindowsPhysicalDrive {
            device_number,
            virtual_disk_identity,
            ..
        } => {
            let disk = facts.disk.as_ref();
            tracing::info!(
                lun,
                backend = "physical drive",
                device_number,
                model = disk.map_or("unknown", |disk| disk.model.as_str()),
                bus = disk.map_or("unknown", |disk| disk.bus.as_str()),
                removable = disk.map_or("unknown", |disk| if disk.removable {
                    "true"
                } else {
                    "false"
                }),
                hardware_serial = disk.map_or("unknown", |disk| disk.serial_number.as_str()),
                capacity_bytes,
                block_size,
                block_count,
                read_only,
                virtual_disk_identity,
                virtual_disk_identity_active = facts.virtual_identity_active.unwrap_or(false),
                offline = facts.disk_protection.as_deref().unwrap_or("unknown"),
                serial,
                "LUN ready"
            );
        }
        LunBackendConfig::WindowsVolume { drive_letter, .. } => tracing::info!(
            lun,
            backend = "volume",
            drive_letter = %drive_letter.to_ascii_uppercase(),
            capacity_bytes,
            block_size,
            block_count,
            read_only,
            serial,
            "LUN ready"
        ),
    }
}

fn build_backend(
    config: &LunBackendConfig,
) -> Result<(Box<dyn StorageBackend>, BackendFacts), ManagementError> {
    match config {
        LunBackendConfig::Memory {
            block_size,
            block_count,
            read_only,
        } => {
            let mut backend = MemoryBackend::new(*block_size, *block_count)?;
            backend.set_read_only(*read_only);
            Ok((Box::new(backend), BackendFacts::default()))
        }
        LunBackendConfig::File {
            path,
            block_size,
            read_only,
            durable_flush,
        } => {
            let mut backend = if *read_only {
                FileBackend::open_read_only(path, *block_size)?
            } else {
                FileBackend::open_read_write(path, *block_size)?
            };
            backend.set_durable_flush(*durable_flush);
            Ok((Box::new(backend), BackendFacts::default()))
        }
        LunBackendConfig::WindowsPhysicalDrive {
            device_number,
            read_only,
            virtual_disk_identity,
        } => build_windows_physical_drive(*device_number, *read_only, *virtual_disk_identity),
        LunBackendConfig::WindowsVolume {
            drive_letter,
            read_only,
        } => build_windows_volume(*drive_letter, *read_only),
    }
}

#[cfg(windows)]
fn windows_access(read_only: bool) -> crate::platform::windows::WindowsStorageAccess {
    if read_only {
        crate::platform::windows::WindowsStorageAccess::ReadOnly
    } else {
        crate::platform::windows::WindowsStorageAccess::ReadWrite
    }
}

#[cfg(windows)]
fn build_windows_physical_drive(
    device_number: u32,
    read_only: bool,
    virtual_disk_identity: bool,
) -> Result<(Box<dyn StorageBackend>, BackendFacts), ManagementError> {
    use crate::platform::windows::{WindowsStorageBackend, physical_disk};

    // read-write backend는 disk를 배타적으로 열어 그 뒤에는 장치 정보를 물을 수 없다.
    // 그래서 열기 전에 묻는다.
    let disk = physical_disk(device_number).map(|disk| DiskFacts {
        model: disk.description(),
        bus: disk.bus_type.to_string(),
        removable: disk.removable,
        serial_number: disk.serial_number,
    });
    let backend =
        WindowsStorageBackend::open_physical_drive(device_number, windows_access(read_only))?;
    let mut facts = BackendFacts {
        disk,
        virtual_identity_active: None,
        disk_protection: backend
            .disk_protection()
            .map(|protection| protection.to_string()),
    };
    if virtual_disk_identity {
        let backend = crate::disk_identity::VirtualDiskIdentity::new(Box::new(backend))?;
        facts.virtual_identity_active = Some(backend.is_active());
        return Ok((Box::new(backend), facts));
    }
    Ok((Box::new(backend), facts))
}

#[cfg(not(windows))]
fn build_windows_physical_drive(
    _device_number: u32,
    _read_only: bool,
    _virtual_disk_identity: bool,
) -> Result<(Box<dyn StorageBackend>, BackendFacts), ManagementError> {
    Err(ManagementError::WindowsBackendUnavailable)
}

#[cfg(windows)]
fn build_windows_volume(
    drive_letter: char,
    read_only: bool,
) -> Result<(Box<dyn StorageBackend>, BackendFacts), ManagementError> {
    Ok((
        Box::new(
            crate::platform::windows::WindowsStorageBackend::open_volume(
                drive_letter,
                windows_access(read_only),
            )?,
        ),
        BackendFacts::default(),
    ))
}

#[cfg(not(windows))]
fn build_windows_volume(
    _drive_letter: char,
    _read_only: bool,
) -> Result<(Box<dyn StorageBackend>, BackendFacts), ManagementError> {
    Err(ManagementError::WindowsBackendUnavailable)
}

#[derive(Debug, thiserror::Error)]
pub enum ManagementError {
    #[error("Target registry state is poisoned")]
    RegistryPoisoned,
    #[error("Target {0:?} already exists")]
    DuplicateTarget(IscsiName),
    #[error("Target {0:?} was not found")]
    TargetNotFound(IscsiName),
    #[error("LUN {0} already exists")]
    DuplicateLun(u64),
    #[error("could not open LUN {lun} ({backend}): {source}")]
    LunBackend {
        lun: u64,
        backend: String,
        source: Box<ManagementError>,
    },
    #[error("Windows storage backend is unavailable on this platform")]
    WindowsBackendUnavailable,
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    SharedScsiTarget(#[from] SharedScsiTargetError),
    #[error(transparent)]
    Chap(#[from] ChapError),
    #[error(transparent)]
    Connection(#[from] ConnectionError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    use crate::Pdu;
    use crate::config::ChapAuthenticationConfig;
    use crate::login::{LoginRequest, TextParameters};
    use crate::opcode::{LoginStage, TaskAttribute};
    use crate::scsi::ScsiCommand;

    const INITIATOR: &str = "iqn.2026-07.example.com:initiator";

    fn target_name(suffix: &str) -> IscsiName {
        IscsiName::parse(&format!("iqn.2026-07.example.com:{suffix}")).unwrap()
    }

    fn memory_lun(lun: u64, block_count: u64, read_only: bool) -> LunConfig {
        LunConfig::new(
            lun,
            LunBackendConfig::Memory {
                block_size: 512,
                block_count,
                read_only,
            },
        )
        .unwrap()
    }

    fn login_request(target: &IscsiName, stage: LoginStage, next: LoginStage, cmd_sn: u32) -> Pdu {
        let text = if stage == LoginStage::Security {
            format!(
                "InitiatorName={INITIATOR}\0TargetName={}\0AuthMethod=None\0",
                target.as_str()
            )
            .into_bytes()
        } else {
            Vec::new()
        };
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
            params: TextParameters::parse(&text),
        })
    }

    fn establish(connection: &mut ConnectionStateMachine, target: &IscsiName) {
        connection
            .receive(login_request(
                target,
                LoginStage::Security,
                LoginStage::Operational,
                10,
            ))
            .unwrap();
        connection.response_sent().unwrap();
        connection
            .receive(login_request(
                target,
                LoginStage::Operational,
                LoginStage::FullFeature,
                11,
            ))
            .unwrap();
        connection.response_sent().unwrap();
    }

    fn read_capacity(cmd_sn: u32, exp_stat_sn: u32) -> Pdu {
        let mut cdb = [0; 16];
        cdb[0] = 0x25;
        Pdu::ScsiCommand(ScsiCommand {
            immediate: false,
            final_: true,
            read: true,
            write: false,
            attr: TaskAttribute::Simple,
            lun: 0,
            initiator_task_tag: cmd_sn,
            expected_data_transfer_length: 8,
            cmd_sn,
            exp_stat_sn,
            cdb,
            immediate_data: Bytes::new(),
        })
    }

    #[test]
    fn existing_connection_observes_runtime_lun_add_and_remove() {
        let api = TargetServiceApi::new();
        let name = target_name("dynamic");
        api.add_target(TargetConfig::new(name.clone())).unwrap();

        let mut connection = api.create_connection(&name, 0x1234, 4).unwrap();
        establish(&mut connection, &name);

        api.add_lun(&name, memory_lun(0, 2, false)).unwrap();
        assert_eq!(
            api.target(&name).unwrap().unwrap().luns,
            vec![LunInfo {
                lun: 0,
                block_size: 512,
                block_count: 2,
                read_only: false,
            }]
        );

        let exp_stat_sn = connection.sequence().unwrap().next_stat_sn();
        let output = connection.receive(read_capacity(11, exp_stat_sn)).unwrap();
        let Some(Pdu::ScsiDataIn(response)) = output.response else {
            panic!("expected READ CAPACITY Data-In");
        };
        assert_eq!(response.status, 0);
        assert_eq!(response.data.as_ref(), &[0, 0, 0, 1, 0, 0, 2, 0]);

        assert!(api.remove_lun(&name, 0).unwrap());
        assert!(api.target(&name).unwrap().unwrap().luns.is_empty());

        let exp_stat_sn = connection.sequence().unwrap().next_stat_sn();
        let output = connection.receive(read_capacity(12, exp_stat_sn)).unwrap();
        let Some(Pdu::ScsiResponse(response)) = output.response else {
            panic!("expected missing-LUN CHECK CONDITION");
        };
        assert_eq!(response.status, 0x02);
        assert_eq!((response.sense[2], response.sense[12]), (0x05, 0x25));
    }

    fn data_in(
        connection: &mut ConnectionStateMachine,
        lun: u64,
        cdb: [u8; 16],
        cmd_sn: u32,
    ) -> Bytes {
        let exp_stat_sn = connection.sequence().unwrap().next_stat_sn();
        let output = connection
            .receive(Pdu::ScsiCommand(ScsiCommand {
                immediate: false,
                final_: true,
                read: true,
                write: false,
                attr: TaskAttribute::Simple,
                lun,
                initiator_task_tag: cmd_sn,
                expected_data_transfer_length: 64,
                cmd_sn,
                exp_stat_sn,
                cdb,
                immediate_data: Bytes::new(),
            }))
            .unwrap();
        let Some(Pdu::ScsiDataIn(response)) = output.response else {
            panic!("expected Data-In for opcode {:#04x}", cdb[0]);
        };
        assert_eq!(response.status, 0);
        response.data
    }

    #[test]
    fn initiator_discovers_and_addresses_every_configured_lun() {
        let api = TargetServiceApi::new();
        let name = target_name("multi-lun");
        let mut config = TargetConfig::new(name.clone());
        config.add_lun(memory_lun(0, 2, false)).unwrap();
        config.add_lun(memory_lun(3, 5, false)).unwrap();
        api.add_target(config).unwrap();

        let mut connection = api.create_connection(&name, 0x1234, 8).unwrap();
        establish(&mut connection, &name);

        // Initiator는 LUN 0에 REPORT LUNS를 보내 목록을 얻는다.
        let mut report_luns = [0; 16];
        report_luns[0] = 0xa0;
        report_luns[9] = 64;
        let list = data_in(&mut connection, 0, report_luns, 11);
        assert_eq!(
            list.as_ref(),
            &[
                0, 0, 0, 16, 0, 0, 0, 0, // LUN list length, reserved
                0, 0, 0, 0, 0, 0, 0, 0, // LUN 0
                0, 3, 0, 0, 0, 0, 0, 0, // LUN 3
            ]
        );

        // 그리고 목록의 8 byte를 그대로 BHS의 LUN field에 넣어 명령을 보낸다.
        let second = u64::from_be_bytes(list[16..24].try_into().unwrap());
        let mut read_capacity = [0; 16];
        read_capacity[0] = 0x25;
        assert_eq!(
            data_in(&mut connection, 0, read_capacity, 12).as_ref(),
            &[0, 0, 0, 1, 0, 0, 2, 0]
        );
        assert_eq!(
            data_in(&mut connection, second, read_capacity, 13).as_ref(),
            &[0, 0, 0, 4, 0, 0, 2, 0]
        );

        // 두 disk는 서로 다른 serial number를 낸다. 기대값은 Target 이름과 LUN 번호의
        // FNV-1a 64를 Python으로 따로 계산한 것이다.
        let mut serial = [0; 16];
        serial[0] = 0x12;
        serial[1] = 1;
        serial[2] = 0x80;
        serial[4] = 64;
        assert_eq!(
            &data_in(&mut connection, 0, serial, 14)[4..],
            b"A94680ED629A9D39"
        );
        assert_eq!(
            &data_in(&mut connection, second, serial, 15)[4..],
            b"A9467DED629A9820"
        );
    }

    #[test]
    fn same_lun_number_on_another_target_is_a_different_device() {
        let api = TargetServiceApi::new();
        let name = target_name("other");
        let mut config = TargetConfig::new(name.clone());
        config.add_lun(memory_lun(0, 2, false)).unwrap();
        api.add_target(config).unwrap();
        // runtime에 추가한 LUN도 같은 Target의 namespace를 쓴다.
        api.add_lun(&name, memory_lun(3, 2, false)).unwrap();

        let mut connection = api.create_connection(&name, 0x1234, 8).unwrap();
        establish(&mut connection, &name);
        let mut serial = [0; 16];
        serial[0] = 0x12;
        serial[1] = 1;
        serial[2] = 0x80;
        serial[4] = 64;
        assert_eq!(
            &data_in(&mut connection, 0, serial, 11)[4..],
            b"981B446759766E9A"
        );
        assert_eq!(
            &data_in(&mut connection, 0x0003_0000_0000_0000, serial, 12)[4..],
            b"981B436759766CE7"
        );
    }

    #[test]
    fn target_registry_rejects_duplicates_and_sorts_status() {
        let api = TargetServiceApi::new();
        let later = target_name("z-disk");
        let earlier = target_name("a-disk");
        api.add_target(TargetConfig::new(later.clone())).unwrap();
        api.add_target(TargetConfig::new(earlier.clone())).unwrap();

        assert!(matches!(
            api.add_target(TargetConfig::new(later.clone())),
            Err(ManagementError::DuplicateTarget(name)) if name == later
        ));
        api.add_lun(&earlier, memory_lun(7, 4, true)).unwrap();
        assert!(matches!(
            api.add_lun(&earlier, memory_lun(7, 8, false)),
            Err(ManagementError::DuplicateLun(7))
        ));

        let status = api.targets().unwrap();
        assert_eq!(status[0].name, earlier);
        assert_eq!(status[1].name, later);
        assert!(!api.remove_lun(&status[0].name, 99).unwrap());
        assert!(api.remove_target(&status[1].name).unwrap());
        assert!(!api.remove_target(&status[1].name).unwrap());
    }

    #[test]
    fn status_and_debug_output_do_not_expose_chap_secret() {
        let api = TargetServiceApi::new();
        let name = target_name("chap");
        let mut config = TargetConfig::new(name.clone());
        config.set_authentication(AuthenticationConfig::Chap(
            ChapAuthenticationConfig::new(
                "initiator".to_owned(),
                b"management-test-secret".to_vec(),
            )
            .unwrap(),
        ));
        api.add_target(config).unwrap();

        let status = api.target(&name).unwrap().unwrap();
        assert_eq!(status.authentication, AuthenticationPolicy::ChapOnly);
        assert!(!format!("{status:?}").contains("management-test-secret"));
        let debug = format!("{api:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("management-test-secret"));
        api.create_connection(&name, 0x1234, 4).unwrap();
    }

    #[test]
    fn backend_open_failure_names_the_lun_and_backend() {
        let path = std::env::temp_dir().join(format!(
            "iscsi-target-missing-image-{}.img",
            std::process::id()
        ));
        let name = IscsiName::parse("iqn.2026-07.example.com:missing-image").unwrap();
        let mut target = TargetConfig::new(name);
        target
            .add_lun(
                LunConfig::new(
                    5,
                    LunBackendConfig::File {
                        path: path.clone(),
                        block_size: 512,
                        read_only: true,
                        durable_flush: false,
                    },
                )
                .unwrap(),
            )
            .unwrap();

        let api = TargetServiceApi::new();
        let error = api.add_target(target).unwrap_err();
        let ManagementError::LunBackend { lun, backend, .. } = &error else {
            panic!("expected LunBackend, got {error:?}");
        };
        assert_eq!(*lun, 5);
        assert_eq!(*backend, format!("file {}", path.display()));
        assert!(error.to_string().starts_with(&format!(
            "could not open LUN 5 (file {}): storage open failed: ",
            path.display()
        )));
        // 실패한 Target은 등록되지 않는다.
        assert!(api.targets().unwrap().is_empty());
    }

    /// 이 thread에서 `run`이 남긴 로그를 모아 돌려준다.
    fn captured_log(run: impl FnOnce()) -> String {
        #[derive(Clone, Default)]
        struct Capture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

        impl std::io::Write for Capture {
            fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buffer);
                Ok(buffer.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let capture = Capture::default();
        let writer = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, run);
        let bytes = capture.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn target_startup_logs_the_target_and_each_opened_lun() {
        let image = std::env::temp_dir().join(format!(
            "iscsi-target-startup-log-{}.img",
            std::process::id()
        ));
        std::fs::write(&image, vec![0u8; 4096 * 3]).unwrap();
        let name = IscsiName::parse("iqn.2026-07.example.com:startup-log").unwrap();
        let mut target = TargetConfig::new(name.clone());
        target.set_authentication(AuthenticationConfig::Chap(
            ChapAuthenticationConfig::new("initiator".to_owned(), b"never-logged-secret".to_vec())
                .unwrap(),
        ));
        target
            .add_lun(
                LunConfig::new(
                    0,
                    LunBackendConfig::Memory {
                        block_size: 512,
                        block_count: 64,
                        read_only: true,
                    },
                )
                .unwrap(),
            )
            .unwrap();
        target
            .add_lun(
                LunConfig::new(
                    7,
                    LunBackendConfig::File {
                        path: image.clone(),
                        block_size: 4096,
                        read_only: false,
                        durable_flush: false,
                    },
                )
                .unwrap(),
            )
            .unwrap();

        let api = TargetServiceApi::new();
        let log = captured_log(|| api.add_target(target).unwrap());
        let serial = |lun| {
            let mut scsi = ScsiTarget::default();
            scsi.set_identity_namespace(name.as_str());
            scsi.lun_serial_number(lun)
        };
        // serial은 INQUIRY가 돌려주는 것과 같은 16자리 hexadecimal이다.
        assert_eq!(serial(0).len(), 16);
        assert_ne!(serial(0), serial(7));
        assert_eq!(
            log,
            format!(
                " INFO Target ready name=\"iqn.2026-07.example.com:startup-log\" \
                 authentication=\"chap\" chap_user=\"initiator\" luns=2\n \
                 INFO LUN ready lun=0 backend=\"memory\" capacity_bytes=32768 block_size=512 \
                 block_count=64 read_only=true serial=\"{}\"\n \
                 INFO LUN ready lun=7 backend=\"file\" path={} capacity_bytes=12288 \
                 block_size=4096 block_count=3 read_only=false durable_flush=false \
                 serial=\"{}\"\n",
                serial(0),
                image.display(),
                serial(7),
            )
        );
        assert!(!log.contains("never-logged-secret"));

        // 실행 중에 더한 LUN도 같은 줄을 남긴다.
        let log = captured_log(|| {
            api.add_lun(
                &name,
                LunConfig::new(
                    1,
                    LunBackendConfig::Memory {
                        block_size: 512,
                        block_count: 8,
                        read_only: false,
                    },
                )
                .unwrap(),
            )
            .unwrap()
        });
        assert_eq!(
            log,
            format!(
                " INFO LUN ready lun=1 backend=\"memory\" capacity_bytes=4096 block_size=512 \
                 block_count=8 read_only=false serial=\"{}\"\n",
                serial(1)
            )
        );
        drop(api);
        let _ = std::fs::remove_file(&image);
    }

    #[test]
    fn failed_startup_logs_no_ready_lines() {
        let name = IscsiName::parse("iqn.2026-07.example.com:startup-failed").unwrap();
        let mut target = TargetConfig::new(name);
        for (lun, path) in [(0, None), (1, Some("missing-startup-log.img"))] {
            let backend = match path {
                None => LunBackendConfig::Memory {
                    block_size: 512,
                    block_count: 8,
                    read_only: false,
                },
                Some(path) => LunBackendConfig::File {
                    path: std::env::temp_dir().join(path),
                    block_size: 512,
                    read_only: true,
                    durable_flush: false,
                },
            };
            target
                .add_lun(LunConfig::new(lun, backend).unwrap())
                .unwrap();
        }
        let api = TargetServiceApi::new();
        let log = captured_log(|| {
            api.add_target(target).unwrap_err();
        });
        assert_eq!(log, "");
    }
}
