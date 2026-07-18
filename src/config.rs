//! daemon, Target, LUN과 인증의 runtime 독립적인 설정 모델.

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::auth::{validate_credentials, ChapCredentials, ChapError};
use crate::login::IscsiName;
use crate::login_policy::{AuthenticationPolicy, TargetLoginPolicy};

pub const DEFAULT_ISCSI_PORT: u16 = 3260;
pub const DEFAULT_MAX_SERVICE_CONNECTIONS: usize = 128;
pub const DEFAULT_MAX_BLOCKING_STORAGE_OPERATIONS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenConfig {
    address: IpAddr,
    port: u16,
}

impl ListenConfig {
    pub fn new(address: IpAddr, port: u16) -> Result<Self, ConfigError> {
        if port == 0 {
            return Err(ConfigError::InvalidPort);
        }
        Ok(Self { address, port })
    }

    pub fn address(self) -> IpAddr {
        self.address
    }

    pub fn port(self) -> u16 {
        self.port
    }

    pub fn socket_addr(self) -> SocketAddr {
        SocketAddr::new(self.address, self.port)
    }
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            address: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            port: DEFAULT_ISCSI_PORT,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ChapAuthenticationConfig {
    username: String,
    secret: Zeroizing<Vec<u8>>,
}

impl ChapAuthenticationConfig {
    pub fn new(username: String, secret: Vec<u8>) -> Result<Self, ConfigError> {
        validate_credentials(&username, &secret)?;
        Ok(Self {
            username,
            secret: Zeroizing::new(secret),
        })
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn credentials(&self) -> Result<ChapCredentials, ChapError> {
        ChapCredentials::new(self.username.clone(), self.secret.to_vec())
    }
}

impl fmt::Debug for ChapAuthenticationConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChapAuthenticationConfig")
            .field("username", &self.username)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AuthenticationConfig {
    #[default]
    None,
    Chap(ChapAuthenticationConfig),
    PreferChap(ChapAuthenticationConfig),
}

impl AuthenticationConfig {
    pub fn policy(&self) -> AuthenticationPolicy {
        match self {
            Self::None => AuthenticationPolicy::NoneOnly,
            Self::Chap(_) => AuthenticationPolicy::ChapOnly,
            Self::PreferChap(_) => AuthenticationPolicy::PreferChap,
        }
    }

    pub fn chap(&self) -> Option<&ChapAuthenticationConfig> {
        match self {
            Self::None => None,
            Self::Chap(config) | Self::PreferChap(config) => Some(config),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LunBackendConfig {
    Memory {
        block_size: u32,
        block_count: u64,
        read_only: bool,
    },
    File {
        path: PathBuf,
        block_size: u32,
        read_only: bool,
        durable_flush: bool,
    },
    WindowsPhysicalDrive {
        device_number: u32,
        read_only: bool,
    },
    WindowsVolume {
        drive_letter: char,
        read_only: bool,
    },
}

impl LunBackendConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        match self {
            Self::Memory {
                block_size,
                block_count,
                ..
            } => validate_geometry(*block_size, *block_count),
            Self::File {
                path, block_size, ..
            } => {
                validate_path(path)?;
                validate_geometry(*block_size, 1)
            }
            Self::WindowsPhysicalDrive { .. } => Ok(()),
            Self::WindowsVolume { drive_letter, .. } if drive_letter.is_ascii_alphabetic() => {
                Ok(())
            }
            Self::WindowsVolume { drive_letter, .. } => {
                Err(ConfigError::InvalidDriveLetter(*drive_letter))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LunConfig {
    lun: u64,
    backend: LunBackendConfig,
}

impl LunConfig {
    pub fn new(lun: u64, backend: LunBackendConfig) -> Result<Self, ConfigError> {
        backend.validate()?;
        Ok(Self { lun, backend })
    }

    pub fn lun(&self) -> u64 {
        self.lun
    }

    pub fn backend(&self) -> &LunBackendConfig {
        &self.backend
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetConfig {
    name: IscsiName,
    authentication: AuthenticationConfig,
    luns: Vec<LunConfig>,
}

impl TargetConfig {
    pub fn new(name: IscsiName) -> Self {
        Self {
            name,
            authentication: AuthenticationConfig::default(),
            luns: Vec::new(),
        }
    }

    pub fn name(&self) -> &IscsiName {
        &self.name
    }

    pub fn authentication(&self) -> &AuthenticationConfig {
        &self.authentication
    }

    pub fn set_authentication(&mut self, authentication: AuthenticationConfig) {
        self.authentication = authentication;
    }

    pub fn luns(&self) -> &[LunConfig] {
        &self.luns
    }

    pub fn add_lun(&mut self, lun: LunConfig) -> Result<(), ConfigError> {
        if self.luns.iter().any(|existing| existing.lun == lun.lun) {
            return Err(ConfigError::DuplicateLun(lun.lun));
        }
        self.luns.push(lun);
        Ok(())
    }

    pub fn login_policy(&self) -> TargetLoginPolicy {
        let mut policy = TargetLoginPolicy::default();
        policy.set_target_name(self.name.clone());
        policy.set_authentication(self.authentication.policy());
        policy
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonConfig {
    listen: ListenConfig,
    max_connections: usize,
    max_blocking_storage_operations: usize,
    targets: Vec<TargetConfig>,
}

impl DaemonConfig {
    pub fn new(listen: ListenConfig, max_connections: usize) -> Result<Self, ConfigError> {
        if max_connections == 0 {
            return Err(ConfigError::InvalidConnectionLimit);
        }
        Ok(Self {
            listen,
            max_connections,
            max_blocking_storage_operations: DEFAULT_MAX_BLOCKING_STORAGE_OPERATIONS,
            targets: Vec::new(),
        })
    }

    pub fn listen(&self) -> ListenConfig {
        self.listen
    }

    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    pub fn max_blocking_storage_operations(&self) -> usize {
        self.max_blocking_storage_operations
    }

    pub fn set_max_blocking_storage_operations(&mut self, value: usize) -> Result<(), ConfigError> {
        if value == 0 {
            return Err(ConfigError::InvalidBlockingStorageLimit);
        }
        self.max_blocking_storage_operations = value;
        Ok(())
    }

    pub fn targets(&self) -> &[TargetConfig] {
        &self.targets
    }

    pub fn add_target(&mut self, target: TargetConfig) -> Result<(), ConfigError> {
        if self
            .targets
            .iter()
            .any(|existing| existing.name == target.name)
        {
            return Err(ConfigError::DuplicateTarget(target.name));
        }
        self.targets.push(target);
        Ok(())
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.listen.port == 0 {
            return Err(ConfigError::InvalidPort);
        }
        if self.max_connections == 0 {
            return Err(ConfigError::InvalidConnectionLimit);
        }
        if self.max_blocking_storage_operations == 0 {
            return Err(ConfigError::InvalidBlockingStorageLimit);
        }
        if self.targets.is_empty() {
            return Err(ConfigError::NoTargets);
        }
        let mut target_names = HashSet::with_capacity(self.targets.len());
        for target in &self.targets {
            if !target_names.insert(&target.name) {
                return Err(ConfigError::DuplicateTarget(target.name.clone()));
            }
            let mut luns = HashSet::with_capacity(target.luns.len());
            for lun in &target.luns {
                if !luns.insert(lun.lun) {
                    return Err(ConfigError::DuplicateLun(lun.lun));
                }
                lun.backend.validate()?;
            }
        }
        Ok(())
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            listen: ListenConfig::default(),
            max_connections: DEFAULT_MAX_SERVICE_CONNECTIONS,
            max_blocking_storage_operations: DEFAULT_MAX_BLOCKING_STORAGE_OPERATIONS,
            targets: Vec::new(),
        }
    }
}

fn validate_geometry(block_size: u32, block_count: u64) -> Result<(), ConfigError> {
    if block_size == 0
        || block_count == 0
        || u64::from(block_size).checked_mul(block_count).is_none()
    {
        return Err(ConfigError::InvalidBlockGeometry {
            block_size,
            block_count,
        });
    }
    Ok(())
}

fn validate_path(path: &Path) -> Result<(), ConfigError> {
    if path.as_os_str().is_empty() {
        return Err(ConfigError::EmptyBackendPath);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("listen port must be in 1..=65535")]
    InvalidPort,
    #[error("max_connections must be greater than zero")]
    InvalidConnectionLimit,
    #[error("max_blocking_storage_operations must be greater than zero")]
    InvalidBlockingStorageLimit,
    #[error("configuration must contain at least one Target")]
    NoTargets,
    #[error("duplicate Target name {0:?}")]
    DuplicateTarget(IscsiName),
    #[error("duplicate LUN {0}")]
    DuplicateLun(u64),
    #[error("block geometry {block_size} * {block_count} is invalid")]
    InvalidBlockGeometry { block_size: u32, block_count: u64 },
    #[error("backend path is empty")]
    EmptyBackendPath,
    #[error("Windows volume drive letter {0:?} is invalid")]
    InvalidDriveLetter(char),
    #[error(transparent)]
    Chap(#[from] ChapError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target_name(suffix: &str) -> IscsiName {
        IscsiName::parse(&format!("iqn.2026-07.example.com:{suffix}")).unwrap()
    }

    #[test]
    fn defaults_use_the_standard_port_and_require_a_target() {
        let config = DaemonConfig::default();
        assert_eq!(config.listen().port(), DEFAULT_ISCSI_PORT);
        assert_eq!(config.listen().address(), IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert_eq!(config.validate(), Err(ConfigError::NoTargets));
        assert_eq!(
            ListenConfig::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
            Err(ConfigError::InvalidPort)
        );
    }

    #[test]
    fn target_and_lun_identifiers_are_unique() {
        let mut config = DaemonConfig::default();
        let mut target = TargetConfig::new(target_name("disk"));
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
        assert_eq!(
            target.add_lun(
                LunConfig::new(
                    0,
                    LunBackendConfig::Memory {
                        block_size: 512,
                        block_count: 1,
                        read_only: true,
                    },
                )
                .unwrap()
            ),
            Err(ConfigError::DuplicateLun(0))
        );
        config.add_target(target.clone()).unwrap();
        assert_eq!(
            config.add_target(target),
            Err(ConfigError::DuplicateTarget(target_name("disk")))
        );
        assert!(config.validate().is_ok());
        let policy = config.targets()[0].login_policy();
        assert_eq!(policy.target_name(), Some(&target_name("disk")));
        assert_eq!(policy.authentication(), AuthenticationPolicy::NoneOnly);
    }

    #[test]
    fn backend_geometry_and_paths_are_validated_without_opening_them() {
        assert!(matches!(
            LunConfig::new(
                0,
                LunBackendConfig::Memory {
                    block_size: 0,
                    block_count: 1,
                    read_only: false,
                }
            ),
            Err(ConfigError::InvalidBlockGeometry { .. })
        ));
        assert_eq!(
            LunConfig::new(
                0,
                LunBackendConfig::File {
                    path: PathBuf::new(),
                    block_size: 512,
                    read_only: false,
                    durable_flush: true,
                }
            ),
            Err(ConfigError::EmptyBackendPath)
        );
        assert_eq!(
            LunConfig::new(
                1,
                LunBackendConfig::WindowsVolume {
                    drive_letter: '1',
                    read_only: true,
                }
            ),
            Err(ConfigError::InvalidDriveLetter('1'))
        );
    }

    #[test]
    fn chap_secret_is_redacted_and_converts_to_runtime_credentials() {
        let chap =
            ChapAuthenticationConfig::new("initiator".to_owned(), b"do-not-log-this".to_vec())
                .unwrap();
        let debug = format!("{chap:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("do-not-log-this"));
        let auth = AuthenticationConfig::Chap(chap);
        assert_eq!(auth.policy(), AuthenticationPolicy::ChapOnly);
        assert_eq!(
            auth.chap().unwrap().credentials().unwrap().username(),
            "initiator"
        );
    }
}
