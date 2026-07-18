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
        for lun in config.luns() {
            target.add_boxed_lun(lun.lun(), build_backend(lun.backend())?);
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

        let backend = build_backend(lun.backend())?;
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

fn build_backend(config: &LunBackendConfig) -> Result<Box<dyn StorageBackend>, ManagementError> {
    match config {
        LunBackendConfig::Memory {
            block_size,
            block_count,
            read_only,
        } => {
            let mut backend = MemoryBackend::new(*block_size, *block_count)?;
            backend.set_read_only(*read_only);
            Ok(Box::new(backend))
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
            Ok(Box::new(backend))
        }
        LunBackendConfig::WindowsPhysicalDrive {
            device_number,
            read_only,
        } => build_windows_physical_drive(*device_number, *read_only),
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
) -> Result<Box<dyn StorageBackend>, ManagementError> {
    Ok(Box::new(
        crate::platform::windows::WindowsStorageBackend::open_physical_drive(
            device_number,
            windows_access(read_only),
        )?,
    ))
}

#[cfg(not(windows))]
fn build_windows_physical_drive(
    _device_number: u32,
    _read_only: bool,
) -> Result<Box<dyn StorageBackend>, ManagementError> {
    Err(ManagementError::WindowsBackendUnavailable)
}

#[cfg(windows)]
fn build_windows_volume(
    drive_letter: char,
    read_only: bool,
) -> Result<Box<dyn StorageBackend>, ManagementError> {
    Ok(Box::new(
        crate::platform::windows::WindowsStorageBackend::open_volume(
            drive_letter,
            windows_access(read_only),
        )?,
    ))
}

#[cfg(not(windows))]
fn build_windows_volume(
    _drive_letter: char,
    _read_only: bool,
) -> Result<Box<dyn StorageBackend>, ManagementError> {
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

    use crate::config::ChapAuthenticationConfig;
    use crate::login::{LoginRequest, TextParameters};
    use crate::opcode::{LoginStage, TaskAttribute};
    use crate::scsi::ScsiCommand;
    use crate::Pdu;

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
}
