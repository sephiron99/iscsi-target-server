//! daemon TOML 설정 파일의 load/save 경계.
//!
//! CHAP secret 본문은 TOML에 허용하지 않고 별도 파일에서만 읽는다. runtime 설정과
//! 직렬화 DTO를 분리해 secret bytes가 직렬화 구현에 도달하지 않도록 한다.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::auth::MAX_CHAP_BINARY_LENGTH;
use crate::config::{
    AuthenticationConfig, ChapAuthenticationConfig, ConfigError, DaemonConfig, ListenConfig,
    LunBackendConfig, LunConfig, TargetConfig, DEFAULT_ISCSI_PORT,
    DEFAULT_MAX_BLOCKING_STORAGE_OPERATIONS, DEFAULT_MAX_SERVICE_CONNECTIONS,
};
use crate::login::{IscsiName, IscsiNameError};

pub const CONFIG_FILE_VERSION: u32 = 1;
pub const MAX_CONFIG_FILE_LENGTH: usize = 1024 * 1024;

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

impl DaemonConfig {
    /// TOML 설정과 참조된 secret 파일을 읽고 전체 설정을 검증한다.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, ConfigFileError> {
        let path = absolute_path(path.as_ref())?;
        let bytes =
            read_bounded_file(&path, MAX_CONFIG_FILE_LENGTH, ConfigFileKind::Configuration)?;
        let input = std::str::from_utf8(&bytes)
            .map_err(|_| ConfigFileError::InvalidUtf8 { path: path.clone() })?;
        let document: ConfigDocument =
            toml::from_str(input).map_err(|error| sanitized_toml_error(input, error))?;
        if document.version != CONFIG_FILE_VERSION {
            return Err(ConfigFileError::UnsupportedVersion(document.version));
        }
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        document.into_runtime(base)
    }

    /// 검증된 설정을 TOML로 원자적으로 저장한다. CHAP secret 본문은 저장하지 않는다.
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<(), ConfigFileError> {
        self.validate()?;
        let path = absolute_path(path.as_ref())?;
        let document = ConfigDocument::from_runtime(self)?;
        let encoded = toml::to_string_pretty(&document)
            .map_err(|error| ConfigFileError::Serialize(error.to_string()))?;
        atomic_write(&path, encoded.as_bytes())
    }
}

impl ChapAuthenticationConfig {
    /// 별도 파일의 raw bytes를 CHAP secret으로 읽고 저장 가능한 참조를 유지한다.
    pub fn load_from_secret_file(
        username: String,
        path: impl AsRef<Path>,
    ) -> Result<Self, ConfigFileError> {
        let path = absolute_path(path.as_ref())?;
        let secret = read_secret_file(&path)?;
        Ok(Self::from_external_secret(username, secret, path)?)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ConfigDocument {
    version: u32,
    #[serde(default)]
    listen: ListenDocument,
    #[serde(default = "default_max_connections")]
    max_connections: usize,
    #[serde(default = "default_max_blocking_storage_operations")]
    max_blocking_storage_operations: usize,
    #[serde(default)]
    targets: Vec<TargetDocument>,
}

impl ConfigDocument {
    fn into_runtime(self, base: &Path) -> Result<DaemonConfig, ConfigFileError> {
        let listen = ListenConfig::new(self.listen.address, self.listen.port)?;
        let mut config = DaemonConfig::new(listen, self.max_connections)?;
        config.set_max_blocking_storage_operations(self.max_blocking_storage_operations)?;
        for target in self.targets {
            config.add_target(target.into_runtime(base)?)?;
        }
        config.validate()?;
        Ok(config)
    }

    fn from_runtime(config: &DaemonConfig) -> Result<Self, ConfigFileError> {
        let listen = config.listen();
        let targets = config
            .targets()
            .iter()
            .map(TargetDocument::from_runtime)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            version: CONFIG_FILE_VERSION,
            listen: ListenDocument {
                address: listen.address(),
                port: listen.port(),
            },
            max_connections: config.max_connections(),
            max_blocking_storage_operations: config.max_blocking_storage_operations(),
            targets,
        })
    }
}

fn default_max_connections() -> usize {
    DEFAULT_MAX_SERVICE_CONNECTIONS
}

fn default_max_blocking_storage_operations() -> usize {
    DEFAULT_MAX_BLOCKING_STORAGE_OPERATIONS
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ListenDocument {
    #[serde(default = "default_listen_address")]
    address: IpAddr,
    #[serde(default = "default_listen_port")]
    port: u16,
}

impl Default for ListenDocument {
    fn default() -> Self {
        Self {
            address: default_listen_address(),
            port: default_listen_port(),
        }
    }
}

fn default_listen_address() -> IpAddr {
    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
}

fn default_listen_port() -> u16 {
    DEFAULT_ISCSI_PORT
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct TargetDocument {
    name: String,
    #[serde(default)]
    authentication: AuthenticationDocument,
    #[serde(default)]
    luns: Vec<LunDocument>,
}

impl TargetDocument {
    fn into_runtime(self, base: &Path) -> Result<TargetConfig, ConfigFileError> {
        let name = IscsiName::parse(&self.name)?;
        let mut target = TargetConfig::new(name);
        target.set_authentication(self.authentication.into_runtime(base)?);
        for lun in self.luns {
            target.add_lun(lun.into_runtime(base)?)?;
        }
        Ok(target)
    }

    fn from_runtime(target: &TargetConfig) -> Result<Self, ConfigFileError> {
        Ok(Self {
            name: target.name().as_str().to_owned(),
            authentication: AuthenticationDocument::from_runtime(
                target.name(),
                target.authentication(),
            )?,
            luns: target
                .luns()
                .iter()
                .map(LunDocument::from_runtime)
                .collect(),
        })
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(
    tag = "method",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case",
    deny_unknown_fields
)]
enum AuthenticationDocument {
    #[default]
    None,
    Chap {
        username: String,
        secret_file: PathBuf,
    },
    PreferChap {
        username: String,
        secret_file: PathBuf,
    },
}

impl AuthenticationDocument {
    fn into_runtime(self, base: &Path) -> Result<AuthenticationConfig, ConfigFileError> {
        let (username, path, prefer) = match self {
            Self::None => return Ok(AuthenticationConfig::None),
            Self::Chap {
                username,
                secret_file,
            } => (username, secret_file, false),
            Self::PreferChap {
                username,
                secret_file,
            } => (username, secret_file, true),
        };
        if path.as_os_str().is_empty() {
            return Err(ConfigFileError::EmptySecretPath);
        }
        let path = resolve_path(base, path);
        let authentication = ChapAuthenticationConfig::load_from_secret_file(username, &path)?;
        Ok(if prefer {
            AuthenticationConfig::PreferChap(authentication)
        } else {
            AuthenticationConfig::Chap(authentication)
        })
    }

    fn from_runtime(
        target: &IscsiName,
        authentication: &AuthenticationConfig,
    ) -> Result<Self, ConfigFileError> {
        let (chap, prefer) = match authentication {
            AuthenticationConfig::None => return Ok(Self::None),
            AuthenticationConfig::Chap(chap) => (chap, false),
            AuthenticationConfig::PreferChap(chap) => (chap, true),
        };
        let secret_file = chap
            .secret_file()
            .ok_or_else(|| ConfigFileError::SecretSourceRequired(target.clone()))?
            .to_path_buf();
        Ok(if prefer {
            Self::PreferChap {
                username: chap.username().to_owned(),
                secret_file,
            }
        } else {
            Self::Chap {
                username: chap.username().to_owned(),
                secret_file,
            }
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "backend",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case",
    deny_unknown_fields
)]
enum LunDocument {
    Memory {
        lun: u64,
        block_size: u32,
        block_count: u64,
        #[serde(default)]
        read_only: bool,
    },
    File {
        lun: u64,
        path: PathBuf,
        block_size: u32,
        #[serde(default)]
        read_only: bool,
        #[serde(default = "default_durable_flush")]
        durable_flush: bool,
    },
    WindowsPhysicalDrive {
        lun: u64,
        device_number: u32,
        #[serde(default)]
        read_only: bool,
        #[serde(default)]
        virtual_disk_identity: bool,
    },
    WindowsVolume {
        lun: u64,
        drive_letter: char,
        #[serde(default)]
        read_only: bool,
    },
}

impl LunDocument {
    fn into_runtime(self, base: &Path) -> Result<LunConfig, ConfigFileError> {
        let (lun, backend) = match self {
            Self::Memory {
                lun,
                block_size,
                block_count,
                read_only,
            } => (
                lun,
                LunBackendConfig::Memory {
                    block_size,
                    block_count,
                    read_only,
                },
            ),
            Self::File {
                lun,
                path,
                block_size,
                read_only,
                durable_flush,
            } => (
                lun,
                LunBackendConfig::File {
                    path: resolve_path(base, path),
                    block_size,
                    read_only,
                    durable_flush,
                },
            ),
            Self::WindowsPhysicalDrive {
                lun,
                device_number,
                read_only,
                virtual_disk_identity,
            } => (
                lun,
                LunBackendConfig::WindowsPhysicalDrive {
                    device_number,
                    read_only,
                    virtual_disk_identity,
                },
            ),
            Self::WindowsVolume {
                lun,
                drive_letter,
                read_only,
            } => (
                lun,
                LunBackendConfig::WindowsVolume {
                    drive_letter,
                    read_only,
                },
            ),
        };
        Ok(LunConfig::new(lun, backend)?)
    }

    fn from_runtime(lun: &LunConfig) -> Self {
        match lun.backend() {
            LunBackendConfig::Memory {
                block_size,
                block_count,
                read_only,
            } => Self::Memory {
                lun: lun.lun(),
                block_size: *block_size,
                block_count: *block_count,
                read_only: *read_only,
            },
            LunBackendConfig::File {
                path,
                block_size,
                read_only,
                durable_flush,
            } => Self::File {
                lun: lun.lun(),
                path: path.clone(),
                block_size: *block_size,
                read_only: *read_only,
                durable_flush: *durable_flush,
            },
            LunBackendConfig::WindowsPhysicalDrive {
                device_number,
                read_only,
                virtual_disk_identity,
            } => Self::WindowsPhysicalDrive {
                lun: lun.lun(),
                device_number: *device_number,
                read_only: *read_only,
                virtual_disk_identity: *virtual_disk_identity,
            },
            LunBackendConfig::WindowsVolume {
                drive_letter,
                read_only,
            } => Self::WindowsVolume {
                lun: lun.lun(),
                drive_letter: *drive_letter,
                read_only: *read_only,
            },
        }
    }
}

fn default_durable_flush() -> bool {
    true
}

fn resolve_path(base: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        base.join(path)
    }
}

fn absolute_path(path: &Path) -> Result<PathBuf, ConfigFileError> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    std::env::current_dir()
        .map(|current| current.join(path))
        .map_err(|source| io_error(ConfigIoOperation::CurrentDirectory, path, source))
}

fn read_secret_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, ConfigFileError> {
    let file =
        File::open(path).map_err(|source| io_error(ConfigIoOperation::OpenSecret, path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error(ConfigIoOperation::Metadata, path, source))?;
    if !metadata.is_file() {
        return Err(ConfigFileError::SecretNotRegularFile(path.to_path_buf()));
    }
    read_bounded(
        file,
        path,
        MAX_CHAP_BINARY_LENGTH,
        ConfigFileKind::Secret,
        metadata.len(),
    )
}

fn read_bounded_file(
    path: &Path,
    limit: usize,
    kind: ConfigFileKind,
) -> Result<Zeroizing<Vec<u8>>, ConfigFileError> {
    let file =
        File::open(path).map_err(|source| io_error(ConfigIoOperation::Open, path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error(ConfigIoOperation::Metadata, path, source))?;
    read_bounded(file, path, limit, kind, metadata.len())
}

fn read_bounded(
    file: File,
    path: &Path,
    limit: usize,
    kind: ConfigFileKind,
    metadata_length: u64,
) -> Result<Zeroizing<Vec<u8>>, ConfigFileError> {
    if metadata_length > limit as u64 {
        return Err(ConfigFileError::FileTooLarge {
            kind,
            path: path.to_path_buf(),
            length: metadata_length,
            limit,
        });
    }
    let capacity = usize::try_from(metadata_length).unwrap_or(limit).min(limit);
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    file.take((limit as u64) + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(ConfigIoOperation::Read, path, source))?;
    if bytes.len() > limit {
        return Err(ConfigFileError::FileTooLarge {
            kind,
            path: path.to_path_buf(),
            length: bytes.len() as u64,
            limit,
        });
    }
    Ok(bytes)
}

fn sanitized_toml_error(input: &str, error: toml::de::Error) -> ConfigFileError {
    let (line, column) = error
        .span()
        .map(|span| line_column(input, span.start))
        .unwrap_or((0, 0));
    ConfigFileError::Toml {
        line: line + 1,
        column: column + 1,
    }
}

fn line_column(input: &str, byte_index: usize) -> (usize, usize) {
    let prefix = &input.as_bytes()[..byte_index.min(input.len())];
    let line = prefix.iter().filter(|byte| **byte == b'\n').count();
    let column = prefix
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(prefix.len(), |position| prefix.len() - position - 1);
    (line, column)
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), ConfigFileError> {
    let mut last_collision = None;
    for _ in 0..16 {
        let temporary_path = temporary_path(path);
        let mut temporary = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last_collision = Some(error);
                continue;
            }
            Err(source) => {
                return Err(io_error(
                    ConfigIoOperation::CreateTemporary,
                    &temporary_path,
                    source,
                ));
            }
        };
        let mut guard = TemporaryFileGuard::new(temporary_path.clone());
        temporary
            .write_all(contents)
            .map_err(|source| io_error(ConfigIoOperation::Write, &temporary_path, source))?;
        temporary
            .sync_all()
            .map_err(|source| io_error(ConfigIoOperation::Sync, &temporary_path, source))?;
        drop(temporary);
        fs::rename(&temporary_path, path)
            .map_err(|source| io_error(ConfigIoOperation::Replace, path, source))?;
        guard.commit();
        return Ok(());
    }
    Err(io_error(
        ConfigIoOperation::CreateTemporary,
        path,
        last_collision.unwrap_or_else(|| std::io::Error::from(std::io::ErrorKind::AlreadyExists)),
    ))
}

fn temporary_path(destination: &Path) -> PathBuf {
    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("config");
    destination.with_file_name(format!(".{name}.tmp-{}-{counter}", std::process::id()))
}

struct TemporaryFileGuard {
    path: PathBuf,
    committed: bool,
}

impl TemporaryFileGuard {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for TemporaryFileGuard {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn io_error(operation: ConfigIoOperation, path: &Path, source: std::io::Error) -> ConfigFileError {
    ConfigFileError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFileKind {
    Configuration,
    Secret,
}

impl fmt::Display for ConfigFileKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration => formatter.write_str("configuration"),
            Self::Secret => formatter.write_str("secret"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfigIoOperation {
    #[error("resolve current directory")]
    CurrentDirectory,
    #[error("open")]
    Open,
    #[error("open secret")]
    OpenSecret,
    #[error("read metadata")]
    Metadata,
    #[error("read")]
    Read,
    #[error("create temporary file")]
    CreateTemporary,
    #[error("write")]
    Write,
    #[error("sync")]
    Sync,
    #[error("replace")]
    Replace,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigFileError {
    #[error("configuration I/O operation {operation} failed for {path:?}: {source}")]
    Io {
        operation: ConfigIoOperation,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("configuration file {path:?} is not valid UTF-8")]
    InvalidUtf8 { path: PathBuf },
    #[error("configuration TOML or schema error at line {line}, column {column}")]
    Toml { line: usize, column: usize },
    #[error("configuration serialization failed: {0}")]
    Serialize(String),
    #[error("configuration version {0} is unsupported")]
    UnsupportedVersion(u32),
    #[error("{kind} file {path:?} is {length} bytes; limit is {limit} bytes")]
    FileTooLarge {
        kind: ConfigFileKind,
        path: PathBuf,
        length: u64,
        limit: usize,
    },
    #[error("CHAP secret-file path is empty")]
    EmptySecretPath,
    #[error("CHAP secret path {0:?} is not a regular file")]
    SecretNotRegularFile(PathBuf),
    #[error(
        "Target {0:?} uses an in-memory CHAP secret and cannot be saved; load it from secret-file"
    )]
    SecretSourceRequired(IscsiName),
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    IscsiName(#[from] IscsiNameError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let counter = TEST_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "iscsi-target-config-{label}-{}-{counter}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_secret(path: &Path, secret: &[u8]) {
        fs::write(path, secret).unwrap();
    }

    fn configuration(secret_file: &str) -> String {
        format!(
            r#"version = 1
max-connections = 16
max-blocking-storage-operations = 4

[listen]
address = "127.0.0.1"
port = 3260

[[targets]]
name = "iqn.2026-07.example.com:disk"

[targets.authentication]
method = "chap"
username = "initiator"
secret-file = "{secret_file}"

[[targets.luns]]
lun = 0
backend = "file"
path = "images/disk.img"
block-size = 512
read-only = false
durable-flush = true
"#
        )
    }

    #[test]
    fn load_resolves_paths_and_save_round_trips_without_secret_bytes() {
        let directory = TestDirectory::new("round-trip");
        let secret_path = directory.path("chap.secret");
        write_secret(&secret_path, b"external-only-secret");
        let config_path = directory.path("target.toml");
        fs::write(&config_path, configuration("chap.secret")).unwrap();

        let config = DaemonConfig::load_from_file(&config_path).unwrap();
        assert_eq!(config.max_connections(), 16);
        assert_eq!(config.max_blocking_storage_operations(), 4);
        assert_eq!(
            config.listen().address(),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
        let target = &config.targets()[0];
        assert_eq!(
            target.authentication().chap().unwrap().secret_file(),
            Some(secret_path.as_path())
        );
        let LunBackendConfig::File { path, .. } = target.luns()[0].backend() else {
            panic!("expected file backend");
        };
        assert_eq!(path, &directory.path("images/disk.img"));

        let saved_path = directory.path("saved.toml");
        config.save_to_file(&saved_path).unwrap();
        let saved = fs::read_to_string(&saved_path).unwrap();
        assert!(saved.contains("secret-file"));
        assert!(!saved.contains("external-only-secret"));
        assert_eq!(DaemonConfig::load_from_file(&saved_path).unwrap(), config);
    }

    #[test]
    fn inline_secret_is_rejected_without_echoing_its_value() {
        let directory = TestDirectory::new("inline-secret");
        let secret_path = directory.path("chap.secret");
        write_secret(&secret_path, b"valid-external-secret");
        let config_path = directory.path("target.toml");
        let input = configuration("chap.secret").replace(
            "secret-file = \"chap.secret\"",
            "secret-file = \"chap.secret\"\nsecret = \"must-never-be-logged\"",
        );
        fs::write(&config_path, input).unwrap();

        let error = DaemonConfig::load_from_file(config_path).unwrap_err();
        assert!(matches!(error, ConfigFileError::Toml { .. }));
        assert!(!format!("{error}").contains("must-never-be-logged"));
        assert!(!format!("{error:?}").contains("must-never-be-logged"));
    }

    #[test]
    fn in_memory_chap_secret_cannot_enter_the_serialization_path() {
        let directory = TestDirectory::new("in-memory-secret");
        let mut config = DaemonConfig::default();
        let name = IscsiName::parse("iqn.2026-07.example.com:memory-secret").unwrap();
        let mut target = TargetConfig::new(name.clone());
        target.set_authentication(AuthenticationConfig::Chap(
            ChapAuthenticationConfig::new(
                "initiator".to_owned(),
                b"must-not-be-serialized".to_vec(),
            )
            .unwrap(),
        ));
        config.add_target(target).unwrap();

        let path = directory.path("target.toml");
        fs::write(&path, "existing configuration").unwrap();
        let error = config.save_to_file(&path).unwrap_err();
        assert!(matches!(
            error,
            ConfigFileError::SecretSourceRequired(ref target_name) if target_name == &name
        ));
        assert!(!format!("{error:?}").contains("must-not-be-serialized"));
        assert_eq!(fs::read_to_string(path).unwrap(), "existing configuration");
    }

    #[test]
    fn programmatic_chap_loaded_from_secret_file_can_be_saved() {
        let directory = TestDirectory::new("external-secret-api");
        let secret_path = directory.path("chap.secret");
        write_secret(&secret_path, b"sensitive-byte-sequence");
        let authentication =
            ChapAuthenticationConfig::load_from_secret_file("initiator".to_owned(), &secret_path)
                .unwrap();
        let mut target =
            TargetConfig::new(IscsiName::parse("iqn.2026-07.example.com:external-secret").unwrap());
        target.set_authentication(AuthenticationConfig::Chap(authentication));
        let mut config = DaemonConfig::default();
        config.add_target(target).unwrap();

        let path = directory.path("target.toml");
        config.save_to_file(&path).unwrap();
        let saved = fs::read_to_string(&path).unwrap();
        assert!(!saved.contains("sensitive-byte-sequence"));
        assert_eq!(DaemonConfig::load_from_file(path).unwrap(), config);
    }

    #[test]
    fn file_sizes_and_schema_version_are_bounded_before_runtime_construction() {
        let directory = TestDirectory::new("limits");
        let oversized = directory.path("oversized.toml");
        fs::write(&oversized, vec![b' '; MAX_CONFIG_FILE_LENGTH + 1]).unwrap();
        assert!(matches!(
            DaemonConfig::load_from_file(oversized),
            Err(ConfigFileError::FileTooLarge {
                kind: ConfigFileKind::Configuration,
                ..
            })
        ));

        let unsupported = directory.path("unsupported.toml");
        fs::write(&unsupported, "version = 2\n").unwrap();
        assert!(matches!(
            DaemonConfig::load_from_file(unsupported),
            Err(ConfigFileError::UnsupportedVersion(2))
        ));

        let oversized_secret = directory.path("oversized.secret");
        write_secret(&oversized_secret, &vec![b'x'; MAX_CHAP_BINARY_LENGTH + 1]);
        assert!(matches!(
            ChapAuthenticationConfig::load_from_secret_file(
                "initiator".to_owned(),
                oversized_secret
            ),
            Err(ConfigFileError::FileTooLarge {
                kind: ConfigFileKind::Secret,
                ..
            })
        ));
    }

    #[test]
    fn all_backend_variants_round_trip_through_toml() {
        let directory = TestDirectory::new("backends");
        let name = IscsiName::parse("iqn.2026-07.example.com:backends").unwrap();
        let mut target = TargetConfig::new(name);
        let backends = [
            LunBackendConfig::Memory {
                block_size: 512,
                block_count: 8,
                read_only: false,
            },
            LunBackendConfig::File {
                path: directory.path("disk.img"),
                block_size: 4096,
                read_only: true,
                durable_flush: false,
            },
            LunBackendConfig::WindowsPhysicalDrive {
                device_number: 3,
                read_only: true,
                virtual_disk_identity: true,
            },
            LunBackendConfig::WindowsVolume {
                drive_letter: 'U',
                read_only: false,
            },
        ];
        for (lun, backend) in backends.into_iter().enumerate() {
            target
                .add_lun(LunConfig::new(lun as u64, backend).unwrap())
                .unwrap();
        }
        let mut config = DaemonConfig::default();
        config.add_target(target).unwrap();
        let path = directory.path("backends.toml");
        config.save_to_file(&path).unwrap();

        assert_eq!(DaemonConfig::load_from_file(path).unwrap(), config);
    }

    #[test]
    fn sample_configuration_loads_and_serves_only_a_memory_disk() {
        // 저장소의 예시 파일이 schema와 어긋나지 않게 한다. 그대로 실행해도 장치를 열지
        // 않도록 활성화된 LUN은 memory backend 하나여야 한다.
        let directory = TestDirectory::new("sample");
        let path = directory.path("sample.toml");
        fs::write(&path, include_str!("../sample.toml")).unwrap();

        let config = DaemonConfig::load_from_file(path).unwrap();
        assert_eq!(config.targets().len(), 1);
        let target = &config.targets()[0];
        assert_eq!(target.authentication(), &AuthenticationConfig::None);
        let backends: Vec<_> = target
            .luns()
            .iter()
            .map(|lun| (lun.lun(), lun.backend().clone()))
            .collect();
        assert_eq!(
            backends,
            [(
                0,
                LunBackendConfig::Memory {
                    block_size: 512,
                    block_count: 1_310_720,
                    read_only: false,
                }
            )]
        );
    }

    #[test]
    fn virtual_disk_identity_defaults_to_off_and_parses_from_its_kebab_case_key() {
        let directory = TestDirectory::new("identity");
        let path = directory.path("identity.toml");
        fs::write(
            &path,
            r#"version = 1

[[targets]]
name = "iqn.2026-10.example.com:identity"

[[targets.luns]]
lun = 0
backend = "windows-physical-drive"
device-number = 2

[[targets.luns]]
lun = 1
backend = "windows-physical-drive"
device-number = 3
virtual-disk-identity = true
"#,
        )
        .unwrap();

        let config = DaemonConfig::load_from_file(path).unwrap();
        let backends: Vec<_> = config.targets()[0]
            .luns()
            .iter()
            .map(|lun| lun.backend().clone())
            .collect();
        assert_eq!(
            backends,
            [
                LunBackendConfig::WindowsPhysicalDrive {
                    device_number: 2,
                    read_only: false,
                    virtual_disk_identity: false,
                },
                LunBackendConfig::WindowsPhysicalDrive {
                    device_number: 3,
                    read_only: false,
                    virtual_disk_identity: true,
                },
            ]
        );
    }
}
