//! 창에서 고치는 설정의 model.
//!
//! [`Settings`]는 화면의 입력 칸과 LUN 목록이 담는 값이고, 서버를 시작하거나 저장할 때
//! 라이브러리의 [`ServerConfig`]로 바꾼다. [`LunForm`]은 LUN dialog의 입력 칸이 담는
//! 값이다. 둘 다 입력을 글자 그대로 들고 있다가 바꿀 때 검증하므로, 검증 규칙과 오류
//! 문구를 창 없이 테스트할 수 있다.
//!
//! 서버가 Target 하나만 허용하므로 model에도 Target은 하나다. CHAP 인증은 아직 창에서
//! 고치지 못하고, 읽어 온 설정의 것을 그대로 지닌다.

use std::net::IpAddr;
use std::path::PathBuf;

use iscsi_target_server::config::{
    DEFAULT_ISCSI_PORT, DEFAULT_MAX_BLOCKING_STORAGE_OPERATIONS, DEFAULT_MAX_SERVICE_CONNECTIONS,
};
use iscsi_target_server::{
    AuthenticationConfig, IscsiName, ListenConfig, LunBackendConfig, LunConfig, ServerConfig,
    TargetConfig,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub target_name: String,
    pub listen_address: String,
    pub listen_port: String,
    /// LUN 번호 순서로 둔다.
    luns: Vec<LunConfig>,
    authentication: AuthenticationConfig,
    max_connections: usize,
    max_blocking_storage_operations: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            target_name: String::new(),
            listen_address: "0.0.0.0".to_owned(),
            listen_port: DEFAULT_ISCSI_PORT.to_string(),
            luns: Vec::new(),
            authentication: AuthenticationConfig::None,
            max_connections: DEFAULT_MAX_SERVICE_CONNECTIONS,
            max_blocking_storage_operations: DEFAULT_MAX_BLOCKING_STORAGE_OPERATIONS,
        }
    }
}

impl Settings {
    /// 새로 만드는 설정. Target 이름을 이 PC의 이름과 지금 날짜로 미리 채운다.
    ///
    /// `unix_seconds`는 1970-01-01 00:00 UTC부터의 초다.
    pub fn new_for(computer_name: &str, unix_seconds: u64) -> Self {
        Self {
            target_name: default_target_name(computer_name, unix_seconds),
            ..Self::default()
        }
    }

    /// 읽어 온 설정을 창에서 고칠 수 있는 모양으로 바꾼다.
    pub fn from_config(config: &ServerConfig) -> Result<Self, String> {
        let [target] = config.targets() else {
            return Err(format!(
                "the server supports exactly one Target; the configuration has {}",
                config.targets().len()
            ));
        };
        let mut luns = target.luns().to_vec();
        luns.sort_by_key(LunConfig::lun);
        Ok(Self {
            target_name: target.name().as_str().to_owned(),
            listen_address: config.listen().address().to_string(),
            listen_port: config.listen().port().to_string(),
            luns,
            authentication: target.authentication().clone(),
            max_connections: config.max_connections(),
            max_blocking_storage_operations: config.max_blocking_storage_operations(),
        })
    }

    /// 입력을 검증해 서버가 쓰는 설정으로 바꾼다.
    pub fn to_config(&self) -> Result<ServerConfig, String> {
        let name = self.target_name.trim();
        if name.is_empty() {
            return Err("Enter the Target name, for example iqn.2026-10.local.test:disk.".into());
        }
        let name = IscsiName::parse(name)
            .map_err(|error| format!("The Target name is not valid: {error}"))?;
        let address: IpAddr = self
            .listen_address
            .trim()
            .parse()
            .map_err(|_| "The listen address must be an IPv4 or IPv6 address.".to_owned())?;
        let port: u16 = self
            .listen_port
            .trim()
            .parse()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| "The port must be a number from 1 to 65535.".to_owned())?;
        if self.luns.is_empty() {
            return Err("Add at least one LUN.".into());
        }

        let mut target = TargetConfig::new(name);
        target.set_authentication(self.authentication.clone());
        for lun in &self.luns {
            target
                .add_lun(lun.clone())
                .map_err(|error| error.to_string())?;
        }
        let listen = ListenConfig::new(address, port).map_err(|error| error.to_string())?;
        let mut config =
            ServerConfig::new(listen, self.max_connections).map_err(|error| error.to_string())?;
        config
            .set_max_blocking_storage_operations(self.max_blocking_storage_operations)
            .map_err(|error| error.to_string())?;
        config
            .add_target(target)
            .map_err(|error| error.to_string())?;
        config.validate().map_err(|error| error.to_string())?;
        Ok(config)
    }

    pub fn luns(&self) -> &[LunConfig] {
        &self.luns
    }

    /// LUN을 넣는다. `replacing`이 있으면 그 번호의 LUN을 바꾸는 것이고, 없으면 새로
    /// 더하는 것이다. 다른 LUN과 번호가 겹치면 거절한다.
    pub fn put_lun(&mut self, replacing: Option<u64>, lun: LunConfig) -> Result<(), String> {
        let taken = self
            .luns
            .iter()
            .any(|existing| existing.lun() == lun.lun() && Some(existing.lun()) != replacing);
        if taken {
            return Err(format!("LUN {} already exists.", lun.lun()));
        }
        if let Some(replacing) = replacing {
            self.luns.retain(|existing| existing.lun() != replacing);
        }
        self.luns.push(lun);
        self.luns.sort_by_key(LunConfig::lun);
        Ok(())
    }

    pub fn remove_lun(&mut self, lun: u64) {
        self.luns.retain(|existing| existing.lun() != lun);
    }

    /// 아직 쓰지 않은 가장 작은 LUN 번호.
    pub fn next_free_lun(&self) -> u64 {
        (0..)
            .find(|candidate| self.luns.iter().all(|lun| lun.lun() != *candidate))
            .unwrap_or_default()
    }

    pub fn authentication_label(&self) -> String {
        match &self.authentication {
            AuthenticationConfig::None => "none".to_owned(),
            AuthenticationConfig::Chap(chap) => format!("CHAP required, user {}", chap.username()),
            AuthenticationConfig::PreferChap(chap) => {
                format!("CHAP preferred, user {}", chap.username())
            }
        }
    }
}

/// 새 설정에 미리 채울 Target 이름. 예: `iqn.2026-10.local.my-pc:disk`.
///
/// IQN은 `iqn.<연도>-<월>.<거꾸로 쓴 domain>:<이름>` 모양이다(RFC 7143 4.2.7.1). 날짜는
/// 원래 그 domain을 가진 시점이지만, 등록된 domain이 없는 PC에서는 만든 달을 쓰고
/// domain 자리에 `local.<PC 이름>`을 둔다. 같은 network의 다른 PC와 겹치지 않으면 된다.
pub fn default_target_name(computer_name: &str, unix_seconds: u64) -> String {
    let (year, month) = year_and_month(unix_seconds);
    format!(
        "iqn.{year:04}-{month:02}.local.{}:disk",
        iqn_label(computer_name)
    )
}

/// PC 이름을 IQN에 쓸 수 있는 글자로 바꾼다. 소문자, 숫자와 `-`만 남긴다.
fn iqn_label(computer_name: &str) -> String {
    /// DNS label 하나의 최대 길이.
    const MAX_LENGTH: usize = 63;
    let label: String = computer_name
        .chars()
        .map(|character| match character.to_ascii_lowercase() {
            lower @ ('a'..='z' | '0'..='9') => lower,
            _ => '-',
        })
        .take(MAX_LENGTH)
        .collect();
    let label = label.trim_matches('-');
    if label.is_empty() {
        "iscsi-target".to_owned()
    } else {
        label.to_owned()
    }
}

/// UTC 기준 연도와 월. 날짜 계산은 Howard Hinnant의 `civil_from_days` 방식이다.
fn year_and_month(unix_seconds: u64) -> (u64, u64) {
    // 0000-03-01을 기준으로 삼으면 윤일이 한 해의 끝에 온다.
    let days = unix_seconds / 86_400 + 719_468;
    let era = days / 146_097;
    let day_of_era = days % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    // 3월을 0으로 세는 달.
    let shifted_month = (5 * day_of_year + 2) / 153;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month)
}

/// LUN dialog에서 고르는 backend 종류.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    File,
    PhysicalDrive,
    Volume,
    Memory,
}

impl BackendKind {
    /// dialog의 목록에 보이는 순서.
    pub const ALL: [Self; 4] = [Self::File, Self::PhysicalDrive, Self::Volume, Self::Memory];

    pub fn label(self) -> &'static str {
        match self {
            Self::File => "Image file",
            Self::PhysicalDrive => "Physical drive",
            Self::Volume => "Volume (drive letter)",
            Self::Memory => "Memory (lost when the server stops)",
        }
    }

    pub fn index(self) -> u32 {
        Self::ALL
            .iter()
            .position(|kind| *kind == self)
            .unwrap_or_default() as u32
    }

    pub fn from_index(index: u32) -> Option<Self> {
        Self::ALL.get(index as usize).copied()
    }

    pub fn uses_path(self) -> bool {
        self == Self::File
    }

    pub fn uses_block_size(self) -> bool {
        matches!(self, Self::File | Self::Memory)
    }

    pub fn uses_block_count(self) -> bool {
        self == Self::Memory
    }

    pub fn uses_device_number(self) -> bool {
        self == Self::PhysicalDrive
    }

    pub fn uses_drive_letter(self) -> bool {
        self == Self::Volume
    }

    pub fn uses_durable_flush(self) -> bool {
        self == Self::File
    }

    pub fn uses_virtual_disk_identity(self) -> bool {
        self == Self::PhysicalDrive
    }
}

/// LUN dialog의 입력 칸. 고른 backend가 쓰지 않는 칸의 값은 무시한다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LunForm {
    pub lun: String,
    pub kind: BackendKind,
    pub path: String,
    pub block_size: String,
    pub block_count: String,
    pub device_number: String,
    pub drive_letter: String,
    pub read_only: bool,
    pub durable_flush: bool,
    pub virtual_disk_identity: bool,
}

impl LunForm {
    /// 새 LUN을 더할 때의 처음 값.
    pub fn new(lun: u64) -> Self {
        Self {
            lun: lun.to_string(),
            kind: BackendKind::File,
            path: String::new(),
            block_size: "512".to_owned(),
            block_count: String::new(),
            device_number: String::new(),
            drive_letter: String::new(),
            read_only: false,
            durable_flush: true,
            virtual_disk_identity: false,
        }
    }

    pub fn from_config(config: &LunConfig) -> Self {
        let mut form = Self::new(config.lun());
        match config.backend() {
            LunBackendConfig::Memory {
                block_size,
                block_count,
                read_only,
            } => {
                form.kind = BackendKind::Memory;
                form.block_size = block_size.to_string();
                form.block_count = block_count.to_string();
                form.read_only = *read_only;
            }
            LunBackendConfig::File {
                path,
                block_size,
                read_only,
                durable_flush,
            } => {
                form.kind = BackendKind::File;
                form.path = path.to_string_lossy().into_owned();
                form.block_size = block_size.to_string();
                form.read_only = *read_only;
                form.durable_flush = *durable_flush;
            }
            LunBackendConfig::WindowsPhysicalDrive {
                device_number,
                read_only,
                virtual_disk_identity,
            } => {
                form.kind = BackendKind::PhysicalDrive;
                form.device_number = device_number.to_string();
                form.read_only = *read_only;
                form.virtual_disk_identity = *virtual_disk_identity;
            }
            LunBackendConfig::WindowsVolume {
                drive_letter,
                read_only,
            } => {
                form.kind = BackendKind::Volume;
                form.drive_letter = drive_letter.to_ascii_uppercase().to_string();
                form.read_only = *read_only;
            }
        }
        form
    }

    /// 입력을 검증해 LUN 설정으로 바꾼다.
    pub fn to_config(&self) -> Result<LunConfig, String> {
        let lun: u64 = parse_number(&self.lun, "The LUN number")?;
        let backend = match self.kind {
            BackendKind::File => {
                let path = self.path.trim();
                if path.is_empty() {
                    return Err("Choose the image file.".into());
                }
                LunBackendConfig::File {
                    path: PathBuf::from(path),
                    block_size: parse_number(&self.block_size, "The block size")?,
                    read_only: self.read_only,
                    durable_flush: self.durable_flush,
                }
            }
            BackendKind::PhysicalDrive => LunBackendConfig::WindowsPhysicalDrive {
                device_number: if self.device_number.trim().is_empty() {
                    return Err("Choose the disk.".into());
                } else {
                    parse_number(&self.device_number, "The disk number")?
                },
                read_only: self.read_only,
                virtual_disk_identity: self.virtual_disk_identity,
            },
            BackendKind::Volume => LunBackendConfig::WindowsVolume {
                drive_letter: parse_drive_letter(&self.drive_letter)?,
                read_only: self.read_only,
            },
            BackendKind::Memory => LunBackendConfig::Memory {
                block_size: parse_number(&self.block_size, "The block size")?,
                block_count: parse_number(&self.block_count, "The block count")?,
                read_only: self.read_only,
            },
        };
        LunConfig::new(lun, backend).map_err(|error| match error {
            iscsi_target_server::ConfigError::InvalidBlockGeometry { .. } => {
                "The block size and block count must be greater than zero.".to_owned()
            }
            other => {
                let mut message = other.to_string();
                // 라이브러리 문구는 소문자로 시작한다. dialog에는 문장으로 보인다.
                if let Some(first) = message.get_mut(..1) {
                    first.make_ascii_uppercase();
                }
                message.push('.');
                message
            }
        })
    }
}

/// 이 PC에 있는 physical disk 하나. LUN dialog의 목록을 만드는 데 쓴다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskEntry {
    pub device_number: u32,
    /// 제조사와 제품 이름. 장치가 알려 주지 않았으면 비어 있다.
    pub description: String,
    pub bus: String,
    pub removable: bool,
    pub size_bytes: Option<u64>,
}

/// LUN dialog의 disk 목록 한 줄.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskChoice {
    pub device_number: u32,
    pub label: String,
}

/// disk 목록을 번호 순서로 만든다.
///
/// `configured`는 고치고 있는 LUN에 적혀 있던 disk 번호다. 그 disk가 지금 연결되어
/// 있지 않아도 목록에 넣어, dialog를 열었다 닫는 것만으로 설정이 바뀌지 않게 한다.
pub fn disk_choices(disks: &[DiskEntry], configured: &str) -> Vec<DiskChoice> {
    let mut choices: Vec<DiskChoice> = disks
        .iter()
        .map(|disk| DiskChoice {
            device_number: disk.device_number,
            label: disk_label(disk),
        })
        .collect();
    if let Ok(configured) = configured.trim().parse::<u32>()
        && choices
            .iter()
            .all(|choice| choice.device_number != configured)
    {
        choices.push(DiskChoice {
            device_number: configured,
            label: format!("Disk {configured} - not connected"),
        });
    }
    choices.sort_by_key(|choice| choice.device_number);
    choices
}

/// `configured`에 적힌 번호가 목록의 몇 번째인지.
pub fn disk_choice_index(choices: &[DiskChoice], configured: &str) -> Option<u32> {
    let configured: u32 = configured.trim().parse().ok()?;
    choices
        .iter()
        .position(|choice| choice.device_number == configured)
        .map(|index| index as u32)
}

/// 예: `Disk 1 - USB SanDisk 3.2Gen1 (USB, removable, 57.3 GiB)`.
fn disk_label(disk: &DiskEntry) -> String {
    let description = if disk.description.is_empty() {
        "Unknown disk"
    } else {
        &disk.description
    };
    let mut details = vec![disk.bus.clone()];
    if disk.removable {
        details.push("removable".to_owned());
    }
    if let Some(size) = disk.size_bytes {
        details.push(format_capacity(size));
    }
    format!(
        "Disk {} - {description} ({})",
        disk.device_number,
        details.join(", ")
    )
}

/// byte 수를 1024 단위로 읽기 쉽게 적는다. 예: `1.5 GiB`.
pub fn format_capacity(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    // 소수점 아래 한 자리로 반올림하되 `.0`은 떼어 낸다.
    let rounded = (value * 10.0).round() / 10.0;
    if rounded.fract() == 0.0 {
        format!("{rounded:.0} {}", UNITS[unit])
    } else {
        format!("{rounded:.1} {}", UNITS[unit])
    }
}

fn parse_number<T: std::str::FromStr>(text: &str, what: &str) -> Result<T, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err(format!("{what} is required."));
    }
    text.parse()
        .map_err(|_| format!("{what} must be a whole number in range."))
}

/// `E`와 `E:`를 모두 받는다.
fn parse_drive_letter(text: &str) -> Result<char, String> {
    let text = text.trim();
    let text = text.strip_suffix(':').unwrap_or(text);
    let mut characters = text.chars();
    match (characters.next(), characters.next()) {
        (Some(letter), None) if letter.is_ascii_alphabetic() => Ok(letter.to_ascii_uppercase()),
        _ => Err("The drive letter must be a single letter such as E.".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 입력을 한 군데 망가뜨리는 함수와, 그때 나와야 하는 오류 문구.
    type Case<T> = (fn(&mut T), &'static str);

    fn memory_lun(lun: u64) -> LunConfig {
        LunConfig::new(
            lun,
            LunBackendConfig::Memory {
                block_size: 512,
                block_count: 64,
                read_only: false,
            },
        )
        .unwrap()
    }

    fn valid_settings() -> Settings {
        let mut settings = Settings {
            target_name: " iqn.2026-10.example.com:disk ".to_owned(),
            listen_address: "127.0.0.1".to_owned(),
            listen_port: " 3261 ".to_owned(),
            ..Settings::default()
        };
        settings.put_lun(None, memory_lun(1)).unwrap();
        settings
    }

    #[test]
    fn settings_become_a_configuration_and_come_back_unchanged() {
        let config = valid_settings().to_config().unwrap();
        assert_eq!(config.listen().socket_addr().to_string(), "127.0.0.1:3261");
        let [target] = config.targets() else {
            panic!("expected one Target");
        };
        assert_eq!(target.name().as_str(), "iqn.2026-10.example.com:disk");
        assert_eq!(target.luns(), [memory_lun(1)]);

        let reloaded = Settings::from_config(&config).unwrap();
        assert_eq!(reloaded.target_name, "iqn.2026-10.example.com:disk");
        assert_eq!(reloaded.listen_port, "3261");
        assert_eq!(reloaded.to_config().unwrap(), config);
    }

    #[test]
    fn invalid_settings_are_rejected_with_a_message_for_the_field() {
        let cases: [Case<Settings>; 6] = [
            (|s| s.target_name = "  ".into(), "Enter the Target name"),
            (
                |s| s.target_name = "not an iqn".into(),
                "The Target name is not valid",
            ),
            (
                |s| s.listen_address = "localhost".into(),
                "The listen address must be",
            ),
            (|s| s.listen_port = "0".into(), "The port must be"),
            (|s| s.listen_port = "65536".into(), "The port must be"),
            (|s| s.remove_lun(1), "Add at least one LUN."),
        ];
        for (change, expected) in cases {
            let mut settings = valid_settings();
            change(&mut settings);
            let error = settings.to_config().unwrap_err();
            assert!(error.starts_with(expected), "{error:?} vs {expected:?}");
        }
    }

    #[test]
    fn configurations_without_exactly_one_target_cannot_be_edited() {
        let error = Settings::from_config(&ServerConfig::default()).unwrap_err();
        assert_eq!(
            error,
            "the server supports exactly one Target; the configuration has 0"
        );
    }

    #[test]
    fn luns_stay_sorted_and_numbers_cannot_collide() {
        let mut settings = Settings::default();
        assert_eq!(settings.next_free_lun(), 0);
        settings.put_lun(None, memory_lun(2)).unwrap();
        settings.put_lun(None, memory_lun(0)).unwrap();
        assert_eq!(settings.next_free_lun(), 1);
        assert_eq!(
            settings.put_lun(None, memory_lun(2)).unwrap_err(),
            "LUN 2 already exists."
        );

        // 같은 번호로 고치는 것과 빈 번호로 옮기는 것은 된다.
        settings.put_lun(Some(2), memory_lun(2)).unwrap();
        settings.put_lun(Some(2), memory_lun(1)).unwrap();
        assert_eq!(
            settings
                .luns()
                .iter()
                .map(LunConfig::lun)
                .collect::<Vec<_>>(),
            [0, 1]
        );
        // 다른 LUN이 쓰는 번호로는 옮기지 못하고, 실패하면 그대로 남는다.
        assert_eq!(
            settings.put_lun(Some(1), memory_lun(0)).unwrap_err(),
            "LUN 0 already exists."
        );
        assert_eq!(settings.luns().len(), 2);

        settings.remove_lun(0);
        assert_eq!(settings.next_free_lun(), 0);
    }

    #[test]
    fn every_backend_round_trips_through_the_form() {
        let backends = [
            LunBackendConfig::Memory {
                block_size: 4096,
                block_count: 256,
                read_only: true,
            },
            LunBackendConfig::File {
                path: PathBuf::from(r"C:\images\disk.img"),
                block_size: 512,
                read_only: false,
                durable_flush: false,
            },
            LunBackendConfig::WindowsPhysicalDrive {
                device_number: 2,
                read_only: false,
                virtual_disk_identity: true,
            },
            LunBackendConfig::WindowsVolume {
                drive_letter: 'E',
                read_only: true,
            },
        ];
        for (lun, backend) in backends.into_iter().enumerate() {
            let config = LunConfig::new(lun as u64, backend).unwrap();
            let form = LunForm::from_config(&config);
            assert_eq!(BackendKind::from_index(form.kind.index()), Some(form.kind));
            assert_eq!(form.to_config().unwrap(), config);
        }
        assert_eq!(BackendKind::from_index(4), None);
    }

    #[test]
    fn form_ignores_fields_of_other_backends_and_accepts_loose_input() {
        let mut form = LunForm::new(3);
        form.kind = BackendKind::Volume;
        form.drive_letter = " e: ".to_owned();
        form.block_size = "not a number".to_owned();
        form.path = "ignored".to_owned();
        assert_eq!(
            form.to_config().unwrap(),
            LunConfig::new(
                3,
                LunBackendConfig::WindowsVolume {
                    drive_letter: 'E',
                    read_only: false,
                },
            )
            .unwrap()
        );
    }

    #[test]
    fn invalid_form_input_is_rejected_with_a_message_for_the_field() {
        let cases: [Case<LunForm>; 10] = [
            (|f| f.lun = "".into(), "The LUN number is required."),
            (
                |f| f.lun = "-1".into(),
                "The LUN number must be a whole number in range.",
            ),
            (
                |f| f.lun = "16384".into(),
                "LUN 16384 is outside the supported range 0..=16383.",
            ),
            (|f| f.path = " ".into(), "Choose the image file."),
            (
                |f| f.block_size = "0".into(),
                "The block size and block count must be greater than zero.",
            ),
            (
                |f| {
                    f.kind = BackendKind::Memory;
                    f.block_count = "".into();
                },
                "The block count is required.",
            ),
            (
                |f| {
                    f.kind = BackendKind::PhysicalDrive;
                    f.device_number = " ".into();
                },
                "Choose the disk.",
            ),
            (
                |f| {
                    f.kind = BackendKind::PhysicalDrive;
                    f.device_number = "4294967296".into();
                },
                "The disk number must be a whole number in range.",
            ),
            (
                |f| {
                    f.kind = BackendKind::Volume;
                    f.drive_letter = "EF".into();
                },
                "The drive letter must be a single letter such as E.",
            ),
            (
                |f| {
                    f.kind = BackendKind::Volume;
                    f.drive_letter = "1".into();
                },
                "The drive letter must be a single letter such as E.",
            ),
        ];
        for (change, expected) in cases {
            let mut form = LunForm::new(0);
            form.path = r"C:\images\disk.img".to_owned();
            change(&mut form);
            assert_eq!(form.to_config().unwrap_err(), expected);
        }
    }

    #[test]
    fn capacity_is_formatted_in_binary_units() {
        assert_eq!(format_capacity(0), "0 B");
        assert_eq!(format_capacity(1023), "1023 B");
        assert_eq!(format_capacity(1024), "1 KiB");
        assert_eq!(format_capacity(32 * 1024), "32 KiB");
        assert_eq!(format_capacity(1536 * 1024 * 1024), "1.5 GiB");
        assert_eq!(format_capacity(640 * 1024 * 1024), "640 MiB");
        assert_eq!(format_capacity(u64::MAX), "16384 PiB");
    }

    fn usb_disk() -> DiskEntry {
        DiskEntry {
            device_number: 1,
            description: "USB SanDisk 3.2Gen1".to_owned(),
            bus: "USB".to_owned(),
            removable: true,
            size_bytes: Some(61_530_439_680),
        }
    }

    #[test]
    fn disk_choices_describe_each_disk_in_number_order() {
        let system = DiskEntry {
            device_number: 0,
            description: String::new(),
            bus: "NVMe".to_owned(),
            removable: false,
            size_bytes: None,
        };
        let choices = disk_choices(&[usb_disk(), system], "");
        assert_eq!(
            choices,
            [
                DiskChoice {
                    device_number: 0,
                    label: "Disk 0 - Unknown disk (NVMe)".to_owned(),
                },
                DiskChoice {
                    device_number: 1,
                    label: "Disk 1 - USB SanDisk 3.2Gen1 (USB, removable, 57.3 GiB)".to_owned(),
                },
            ]
        );
        // 새 LUN에는 고른 disk가 없다.
        assert_eq!(disk_choice_index(&choices, ""), None);
        assert_eq!(disk_choice_index(&choices, " 1 "), Some(1));
    }

    #[test]
    fn configured_disk_that_is_not_connected_stays_in_the_list() {
        let choices = disk_choices(&[usb_disk()], "0");
        assert_eq!(
            choices,
            [
                DiskChoice {
                    device_number: 0,
                    label: "Disk 0 - not connected".to_owned(),
                },
                DiskChoice {
                    device_number: 1,
                    label: "Disk 1 - USB SanDisk 3.2Gen1 (USB, removable, 57.3 GiB)".to_owned(),
                },
            ]
        );
        assert_eq!(disk_choice_index(&choices, "0"), Some(0));

        // 연결되어 있으면 한 번만 나오고, 숫자가 아닌 값은 무시한다.
        assert_eq!(disk_choices(&[usb_disk()], "1").len(), 1);
        assert_eq!(disk_choices(&[usb_disk()], "x").len(), 1);
        assert_eq!(disk_choice_index(&choices, "x"), None);
    }

    #[test]
    fn new_settings_get_a_valid_target_name_from_the_pc_and_the_date() {
        // 2026-10-12 07:11:38 UTC
        let settings = Settings::new_for("DESKTOP-AB12CD", 1_791_789_098);
        assert_eq!(
            settings.target_name,
            "iqn.2026-10.local.desktop-ab12cd:disk"
        );
        IscsiName::parse(&settings.target_name).unwrap();
        // 이름 말고는 빈 설정과 같다.
        assert_eq!(
            Settings {
                target_name: String::new(),
                ..settings
            },
            Settings::default()
        );
    }

    #[test]
    fn target_name_uses_only_characters_an_iqn_allows() {
        let name = |computer_name: &str| default_target_name(computer_name, 0);
        assert_eq!(name("My_PC 01"), "iqn.1970-01.local.my-pc-01:disk");
        assert_eq!(name("--서버--"), "iqn.1970-01.local.iscsi-target:disk");
        assert_eq!(name(""), "iqn.1970-01.local.iscsi-target:disk");
        let long = name(&"a".repeat(200));
        assert_eq!(long.len(), "iqn.1970-01.local.:disk".len() + 63);
        for computer_name in ["My_PC 01", "--서버--", "", "a.b:c", &"a".repeat(200)] {
            IscsiName::parse(&name(computer_name)).unwrap();
        }
    }

    #[test]
    fn year_and_month_follow_the_calendar_across_leap_years() {
        const DAY: u64 = 86_400;
        assert_eq!(year_and_month(0), (1970, 1));
        assert_eq!(year_and_month(31 * DAY - 1), (1970, 1));
        assert_eq!(year_and_month(31 * DAY), (1970, 2));
        // 2000-02-29와 그 다음 날
        assert_eq!(year_and_month(951_782_400), (2000, 2));
        assert_eq!(year_and_month(951_868_800), (2000, 3));
        // 2023-12-31 23:59:59와 2024-01-01 00:00:00
        assert_eq!(year_and_month(1_704_067_199), (2023, 12));
        assert_eq!(year_and_month(1_704_067_200), (2024, 1));
        // 2100년은 윤년이 아니다: 2100-02-28 다음 날은 3월 1일
        assert_eq!(year_and_month(4_107_456_000), (2100, 2));
        assert_eq!(year_and_month(4_107_542_400), (2100, 3));
    }
}
